#!/usr/bin/env python3
"""
ML Defense System for Ryu Controller
Detecta ataques usando las reglas del Decision Tree y toma contramedidas automáticas

Uso: Agregar al comando del controller en docker-compose.yaml
command: "scripts/dc_switch_1.py scripts/ml_defender.py --observe-links"
"""

import os
import time
import json

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import icmp
from ryu.lib import hub
from base_switch import BaseSwitch

RULES_PATH = os.getenv("RULES_PATH", "/home/auser/scripts/dt_rules.json")

FEATURE_COLUMNS = [
    'rx_pkts', 'tx_pkts', 'rx_bytes', 'tx_bytes',
    'drops', 'errors', 'collisions',
    'rx_pps', 'tx_pps', 'rx_bps', 'tx_bps',
    'avg_packet_size_rx', 'avg_packet_size_tx', 'rx_tx_ratio'
]

POLL_TIME = int(os.getenv("DEFENDER_POLLTIME", "5"))
DdosThreshold = int(os.getenv("DDOS_THRESHOLD", "1000"))
BLOCK_TIMEOUT = int(os.getenv("BLOCK_TIMEOUT", "30"))

BLOCKED_PORTS = {}

ATTACK_STATS = {}

class MLDefense(BaseSwitch):
    """
    Sistema de defensa basado en ML con Decision Tree (reglas exportadas)
    Detecta ataques y toma contramedidas automáticamente
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MLDefense, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.dt_rules = None
        self.load_rules()
        self.monitor_thread = hub.spawn(self._monitor)
        
        print("=" * 60)
        print("🛡️  ML DEFENSE SYSTEM - Decision Tree")
        print("=" * 60)
        print(f"Reglas: {RULES_PATH}")
        print(f"Polltime: {POLL_TIME}s")
        print(f"Umbral DDoS: {DdosThreshold} PPS")
        print(f"Block timeout: {BLOCK_TIMEOUT}s")
        print(f"Contramedidas: Bloqueo automático + Desbloqueo")
        print("=" * 60)

    def load_rules(self):
        """Cargar las reglas del Decision Tree exportadas"""
        try:
            if os.path.exists(RULES_PATH):
                with open(RULES_PATH, 'r') as f:
                    data = json.load(f)
                    self.dt_rules = data['rules']
                    print(f"✅ Reglas DT cargadas: {len(self.dt_rules)} reglas")
            else:
                print(f"⚠️ Reglas no encontradas: {RULES_PATH}")
                print("⚠️ Usando detección por umbrales")
                self.dt_rules = None
        except Exception as e:
            print(f"❌ Error al cargar reglas: {e}")
            self.dt_rules = None

    def predict_dt(self, features):
        """Predicción usando las reglas exportadas del DT"""
        if not self.dt_rules:
            return None
            
        sample = dict(zip(FEATURE_COLUMNS, features))
        
        for rule in self.dt_rules:
            match = True
            for condition in rule['path']:
                feature = condition['feature']
                value = sample.get(feature, 0)
                
                if condition['op'] == '<=':
                    if not (value <= condition['threshold']):
                        match = False
                        break
                else:
                    if not (value > condition['threshold']):
                        match = False
                        break
            
            if match:
                return rule['prediction']
        
        return 0

    def _monitor(self):
        """Monitoreo continuo del tráfico"""
        while True:
            for dp in self.datapaths.values():
                self.check_traffic(dp)
            hub.sleep(POLL_TIME)

    def check_traffic(self, datapath):
        """Verificar tráfico de un switch"""
        try:
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
            datapath.send_msg(req)
            
        except Exception as e:
            pass

    def detect_attack_type(self, features, rx_pps, tx_pps):
        """Detectar el tipo de ataque basado en características del tráfico"""
        avg_pkt_size_rx = features[11]
        avg_pkt_size_tx = features[12]
        rx_bytes = features[2]
        tx_bytes = features[3]
        
        if avg_pkt_size_rx < 100:
            if tx_pps > rx_pps * 10:
                return "UDP_FLOOD"
            elif rx_pps > 5000:
                return "ICMP_FLOOD"
        
        if avg_pkt_size_rx < 60 and rx_pps > DdosThreshold:
            return "TCP_SYN_FLOOD"
        
        if rx_bytes > tx_bytes * 50:
            return "HTTP_FLOOD"
        
        return "DDoS_GENERICO"

    def apply_countermeasure(self, datapath, port, attack_type):
        """Aplicar contramedida específica según el tipo de ataque"""
        key = (datapath.id, port)
        
        if key in BLOCKED_PORTS:
            BLOCKED_PORTS[key]['block_time'] = time.time()
            BLOCKED_PORTS[key]['attack_count'] += 1
            return
            
        BLOCKED_PORTS[key] = {
            'block_time': time.time(),
            'attack_type': attack_type,
            'attack_count': 1
        }
        
        self.logger.warning(f"🛡️ Aplicando contramedida en switch {datapath.id}, puerto {port}")
        self.logger.warning(f"   Tipo de ataque detectado: {attack_type}")
        
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(in_port=port)
        
        actions = [parser.OFPActionOutput(ofproto.OFPPC_NO_FWD)]
        
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        msg = parser.OFPFlowMod(
            datapath=datapath,
            priority=1000,
            match=match,
            instructions=inst,
            hard_timeout=BLOCK_TIMEOUT
        )
        
        datapath.send_msg(msg)
        
        print(f"\n{'='*60}")
        print(f"🚨 ATAQUE DETECTADO")
        print(f"{'='*60}")
        print(f"   Switch: {datapath.id}")
        print(f"   Puerto: {port}")
        print(f"   Tipo:   {attack_type}")
        print(f"   Acció:  Puerto BLOQUEADO")
        print(f"   Tiempo: Se desbloqueará en {BLOCK_TIMEOUT}s si el tráfico normaliza")
        print(f"{'='*60}\n")

    def unblock_port(self, switch_id, port):
        """Desbloquear un puerto"""
        if switch_id not in self.datapaths:
            return
            
        datapath = self.datapaths[switch_id]
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        match = parser.OFPMatch(in_port=port)
        
        msg = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match
        )
        
        datapath.send_msg(msg)
        
        attack_type = BLOCKED_PORTS.get((switch_id, port), {}).get('attack_type', 'Unknown')
        
        print(f"\n{'='*60}")
        print(f"✅ TRÁFICO NORMALIZADO")
        print(f"{'='*60}")
        print(f"   Switch: {switch_id}")
        print(f"   Puerto: {port}")
        print(f"   Tipo de ataque bloqueado: {attack_type}")
        print(f"{'='*60}\n")
        
        self.logger.warning(f"✅ Puerto {port} desbloqueado en switch {switch_id} - Tráfico normalizado")

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def port_stats_reply_handler(self, ev):
        """Procesar estadísticas de puertos"""
        body = ev.msg.body
        
        switch_id = ev.msg.datapath.id
        
        for stat in body:
            features = self.extract_features(stat)
            
            if features is None:
                continue
                
            rx_pps = features[7]
            tx_pps = features[8]
            port = stat.port_no
            
            key = (switch_id, port)
            
            is_attack = False
            attack_type = "NORMAL"
            
            if self.dt_rules is not None:
                try:
                    prediction = self.predict_dt(features)
                    
                    if prediction == 1:
                        is_attack = True
                        attack_type = self.detect_attack_type(features, rx_pps, tx_pps)
                        self.logger.warning(f"⚠️ ATAQUE DETECTADO (ML-DT) en switch {switch_id}, puerto {port} - Tipo: {attack_type}")
                except Exception as e:
                    pass
            else:
                if rx_pps > DdosThreshold or tx_pps > DdosThreshold:
                    is_attack = True
                    attack_type = self.detect_attack_type(features, rx_pps, tx_pps)
                    self.logger.warning(f"⚠️ ATAQUE DETECTADO (UMBRAL) en switch {switch_id}, puerto {port} - PPS: {max(rx_pps, tx_pps):.0f} - Tipo: {attack_type}")
            
            if is_attack:
                self.apply_countermeasure(ev.msg.datapath, port, attack_type)
            
            if key in BLOCKED_PORTS:
                block_time = BLOCKED_PORTS[key]['block_time']
                if time.time() - block_time >= BLOCK_TIMEOUT:
                    if rx_pps < DdosThreshold and tx_pps < DdosThreshold:
                        self.unblock_port(switch_id, port)
                        del BLOCKED_PORTS[key]
                    else:
                        BLOCKED_PORTS[key]['block_time'] = time.time()

    def extract_features(self, stat):
        """Extraer features del puerto"""
        try:
            rx_pkts = stat.rx_packets
            tx_pkts = stat.tx_packets
            rx_bytes = stat.rx_bytes
            tx_bytes = stat.tx_bytes
            drops = stat.rx_errors
            errors = stat.tx_errors
            collisions = 0
            
            rx_pps = rx_pkts / POLL_TIME if POLL_TIME > 0 else 0
            tx_pps = tx_pkts / POLL_TIME if POLL_TIME > 0 else 0
            rx_bps = rx_bytes / POLL_TIME if POLL_TIME > 0 else 0
            tx_bps = tx_bytes / POLL_TIME if POLL_TIME > 0 else 0
            
            if rx_pkts > 0:
                avg_pkt_size_rx = rx_bytes / rx_pkts
            else:
                avg_pkt_size_rx = 0
                
            if tx_pkts > 0:
                avg_pkt_size_tx = tx_bytes / tx_pkts
            else:
                avg_pkt_size_tx = 0
                
            if tx_pps > 0:
                rx_tx_ratio = rx_pps / tx_pps
            else:
                rx_tx_ratio = 0
                
            return [
                rx_pkts, tx_pkts, rx_bytes, tx_bytes,
                drops, errors, collisions,
                rx_pps, tx_pps, rx_bps, tx_bps,
                avg_pkt_size_rx, avg_pkt_size_tx, rx_tx_ratio
            ]
        except:
            return None

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        """Registrar/desregistrar switches"""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
            print(f"✅ Switch registrado: {datapath.id}")
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

def main():
    """Función principal para ejecutar desde Mininet CLI"""
    print("\n" + "=" * 60)
    print("🛡️  ML DEFENSE SYSTEM - Decision Tree")
    print("=" * 60)
    print("Este sistema se debe cargar en el controlador Ryu")
    print("Agregar al comando del controller en docker-compose.yaml:")
    print("command: scripts/dc_switch_1.py scripts/ml_defender.py")
    print("=" * 60)

if __name__ == "__main__":
    main()

FROM python:3.8-slim

RUN pip install --no-cache-dir ryu==4.34 scikit-learn joblib pandas numpy

WORKDIR /home/auser

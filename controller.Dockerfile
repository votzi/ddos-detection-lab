FROM martimy/ryu-flowmanager

RUN pip install scikit-learn joblib pandas numpy --quiet

WORKDIR /home/auser

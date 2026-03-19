FROM martimy/ryu-flowmanager

RUN pip install --no-cache-dir \
    scikit-learn==0.22 \
    joblib \
    numpy

WORKDIR /home/auser

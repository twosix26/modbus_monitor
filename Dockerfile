FROM docker.leaniot.cn/python3-pip

WORKDIR /app
COPY . .

RUN pip3 install configparser gevent pymodbus six -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com

ENV INVERTER_HOST 192.168.1.60
ENV INVERTER_PORT 502

EXPOSE 10010

CMD ["python3", "./monitor.py"]


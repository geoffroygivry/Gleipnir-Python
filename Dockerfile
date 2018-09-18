FROM ubuntu
ADD . /code
WORKDIR /code
USER root
# Update the repository sources list
RUN apt-get update -y
RUN apt-get upgrade -y

RUN export DEBIAN_FRONTEND=noninteractive

RUN apt-get install -y tzdata nano
RUN ln -fs /usr/share/zoneinfo/America/New_York /etc/localtime
RUN dpkg-reconfigure --frontend noninteractive tzdata

# Install pip, Python and matplotlib required libraries
RUN apt-get update && apt-get install -y python3 python3-dev python3-tk python3-pip \
    libxft-dev libfreetype6 libfreetype6-dev libmysqlclient-dev
RUN pip3 install --no-cache-dir -r requirements.txt
CMD python3 atlas/server.py

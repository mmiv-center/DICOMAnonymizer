FROM ubuntu:18.04

RUN apt-get update -qq && apt-get install -yq build-essential \
    cmake git wget libxml2-dev libxslt1-dev libjpeg-dev

# build gdcm and the executable
RUN cd /root && git clone https://github.com/mmiv-center/DICOMAnonymizer.git && cd DICOMAnonymizer && \
    wget https://github.com/malaterre/GDCM/archive/v2.8.9.tar.gz && \
    tar xzvf v2.8.9.tar.gz && mkdir gdcm-build && cd gdcm-build && cmake ../GDCM-2.8.9 && \
    make
#    && cd .. && cmake . && make

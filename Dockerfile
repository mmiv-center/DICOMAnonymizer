FROM ubuntu:18.04

RUN apt-get update -qq && apt-get install -yq build-essential \
    cmake git wget libxml2-dev libxslt1-dev libjpeg-dev expat

# build gdcm and the executable
RUN cd /root && git clone https://github.com/mmiv-center/DICOMAnonymizer.git && cd DICOMAnonymizer && \
    wget https://github.com/malaterre/GDCM/archive/v2.8.9.tar.gz && \
    tar xzvf v2.8.9.tar.gz && mkdir gdcm-build && cd gdcm-build && cmake -DGDCM_BUILD_SHARED_LIBS=ON ../GDCM-2.8.9 && \
    make && cd .. && cmake . && make

ENV ND_ENTRYPOINT="/startup.sh"

RUN echo '#!/usr/bin/env bash' >> $ND_ENTRYPOINT \
    && echo 'set +x' >> $ND_ENTRYPOINT \
    && echo 'umask 0000' >> $ND_ENTRYPOINT \
    && echo '/root/DICOMAnonymizer/anonymize $*' >> $ND_ENTRYPOINT \
    && chmod 777 $ND_ENTRYPOINT

ENTRYPOINT [ "/startup.sh" ]

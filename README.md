# DICOM Anonymizer using gdcm

This source code demonstrates how to anonymize DICOM files based on the DICOM PS 3.15 AnnexE. We provide a Dockerfile that can be used to build the executable and to run anonymizations.


## Build the container

Clone this repository and:
```
docker build -t anonymizer -f Dockerfile .
```

## Run the container on a directory

If the data is stored in the current directory 'data' this call would anonymize all images in the directory
using the PatientName/PatientID UUUUUU.
```
docker run --rm -it -v `pwd`/data:/input -v /tmp/:/output anonymizer \
           --input /input --output /output --patientid UUUUUU \
	   --dateincrement 42 --byseries --numthreads 4 
```

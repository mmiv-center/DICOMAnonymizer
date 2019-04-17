# DICOM Anonymizer using gdcm

This source code demonstrates how to anonymize DICOM files based on the DICOM PS 3.15 AnnexE. We provide a Dockerfile that can be used to build the executable and to run anonymizations.


## Build the container

Clone this repository and:
```
> docker build -t anonymizer .
> docker run --rm -it anonymizer
USAGE: anonymize [options]

Options:
  --help               Anonymize DICOM images. Read DICOM image series and write
                       out an annonymized version of the files based on the
                       recommendations of the cancer imaging archive.
  --input, -i          Input directory.
  --output, -o         Output directory.
  --patientid, -p      Patient ID after anonymization.
  --dateincrement, -d  Number of days that should be added to dates.
  --exportanon, -a     Writes the anonymization structure as a json file to disk
                       and quits the program.
  --byseries, -b       Writes each DICOM file into a separate directory by image
                       series.
  --numthreads, -t     How many threads should be used (default 4).

Examples:
  anonymize --input directory --output directory --patientid bla --dateincrement
42
  anonymize --help
```

## Run the container on a directory

If the data is stored in the current directory 'data' this call would anonymize all images in the directory
using the PatientName/PatientID UUUUUU.
```
docker run --rm -it -v `pwd`/data:/input -v /tmp/:/output anonymizer \
           --input /input --output /output --patientid UUUUUU \
	   --dateincrement 42 --byseries --numthreads 4 
```

## Anonymization rules

The tags that this program will anonymize are described in a JSON file that can be exported from the executable with:
```
docker run --rm -it anonymizer --exportanon rules.json
```


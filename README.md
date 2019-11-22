# A fast DICOM anonymizer

This source code demonstrates how to anonymize DICOM files based on the DICOM PS 3.15 AnnexE. I provide a Dockerfile that can be used to build the executable and to run anonymizations. Entries such as uid entries are replaced with hash values. This ensures that partial runs of a studies DICOM files can be merged afterwards. This project is written in C++ using the gdcm library and multiple threads to accelerate processing.

Warning: The operation performed by this tool is a 'soft' de-identification. Instead of a white list of allowed tags the tool
keeps a list of tags known to frequently contain personal identifying information (PII) and replaces only those. On the command line you
specify a patient identifier (PatientID/PatientName). Only if you do not keep a mapping of the new and the old identifier this is 
considered an _anonymization_. If such a list exists the operation performed is a _de-identification_ (permits a later re-identification).

I suggest to review files generated by this tool for additional PII information that might be present in text fields. 

For a more flexible anonymizer please see the CTP DICOM Anonymizer project.

## Build
The executable can be compiled or created inside a docker container. Here the instructions on how to build and run the docker container. Look at the Dockerfile to see how the build is done locally.

Clone this repository and:
```
> docker build -t anonymizer .
> docker run --rm -it anonymizer
USAGE: anonymize [options]

Options:
  --help               Anonymize DICOM images. Read DICOM image series and write
                       out an anonymized version of the files based on the
                       recommendations of the cancer imaging archive.
  --input, -i          Input directory.
  --output, -o         Output directory.
  --patientid, -p      Patient ID after anonymization (default is "hashuid" to hash the
                       existing id).
  --projectname, -j    Project name.
  --sitename, -s       Site name.
  --dateincrement, -d  Number of days that should be added to dates.
  --exportanon, -a     Writes the anonymization structure as a json file to disk
                       and quits the program. There is no way to import a new
                       file currently.
  --byseries, -b       Writes each DICOM file into a separate directory by image
                       series.
  --tagchange, -P      Changes the default behavior for a tag in the build-in
                       rules.
  --numthreads, -t     How many threads should be used (default 4).

Examples:
  anonymize --input directory --output directory --patientid bla -d 42 -b
  anonymize --exportanon rules.json
  anonymize -j test --tagchange "0008,0080=PROJECTNAME" \
            --tagchange "0008,0081=bla" --exportanon rules.json
  anonymize --help
```

## Run

If the data is stored in a directory 'data' underneath the current directory this call would anonymize all
images in the data directory (and all sub-directories) using the PatientName/PatientID UUUUUU and the project
name MMIV. Dates would be incremented by 42 days and the output would contain different directories for each
image series.
```
docker run --rm -it -v `pwd`/data:/input -v /tmp/:/output anonymizer \
           --input /input --output /output --patientid UUUUUU \
	   --dateincrement 42 --byseries --numthreads 4 \
	   --projectname MMIV
```
There will be 4 threads running in parallel during the anonymization. This can drastically improve the speed of
anonymization for large numbers of DICOM files. Here an example of the range of processing times for 261,000 files
(single study) on a 16 core machine:

| #threads  | time |
|---|---|
| 1  | 8m6.334s  |
| 2  | 4m22.521s |
| 5  | 1m58.695s |
| 8  | 1m31.035s |
| 16 | 1m18.328s |

After anonymization the DICOM tag 0012:0062 (PatientIdentityRemoved) will have the value "YES".

## Anonymization rules

The tags that this program will anonymize are described in a JSON file that can be exported from the executable with:
```
docker run --rm -it anonymizer --exportanon rules.json
```
The option --tagchange can be used to change the build-in rules. In the help example the placeholder PROJECTNAME is used to
store the value of option -j (test) in the tag for InstitutionName (0008,0080). The default rule for this tag specifies that
the value is deleted - in our PACS we use that tag to indicate the project name.

It is important to apply the arguments to the program in the correct order. First we set the name of the project and change
rule, then we export the rules.

### Using data in multiple projects

Our PACS system stores only a single copy per SOPInstanceUID - which makes sense. In order to support data that is project
specific I change the hashing algorithm (hashuid+PROJECTNAME) to include the projects name (-j option) for tags that relate
to image, series, study and frame of reference uids. This generates full copies of the data, one for each project. Deleting
data from one project does not influence the same data used in another project!
# A fast DICOM anonymizer

This source code demonstrates how to anonymize DICOM files based on the DICOM PS 3.15 AnnexE. I provide a Dockerfile that can be used to build the executable and to run anonymizations. Entries such as uid entries are replaced with hash values. This ensures that partial runs of a studies DICOM files can be merged afterwards. This project is written in C++ using the gdcm library and multiple threads to accelerate processing.

Warning: The operation performed by this tool is a 'soft' de-identification. Instead of a list of allowed tags the tool
keeps a list of tags known to frequently contain personal identifying information (PII) and replaces only those. On the command line you
specify a patient identifier (PatientID/PatientName). Only if you do not keep a mapping of the new and the old identifier this is 
considered an _anonymization_. If such a list exists the operation performed is a _de-identification_ (permits a later re-identification).

I suggest to review files generated by this tool for additional PII information that might be present in text fields. 

For a more flexible anonymizer please see the CTP DICOM Anonymizer project.

### Unique features

 - fast de-identification (multi-threaded, C++)
 - de-identifies data inside sequences instead of deleting them so overlays survive the procedure

### Limitations

This tool has been written to work as an importer for a (vendor neutral) PACS system. In such a setup data de-identified from the same participant is expected to align with previous data for the same participant and study if the same participant ID and name is used. This is achieved by using study instance uids that are hashed. Series that comes later should therefore match at the study level. It is not possible to recover the original patient ID, patient name and study/series/image instance UIDs from the de-identified fields as no tracking information is stored in the DICOM files. But, identical input data will result in the same hashes. This can be seen as an implicit coupling list - a price we have to pay to be able to use the tool in our research PACS during the data capture stage of a project.

The used SHA256 algorithm for hashing per project is very fast to compute. This will allow an attacker to create many random tries for a brute-force attack. At the worst case this would allow the attacker to recover the original study/series/image instance UIDs. PatientID and PatientName tags are set manually and are therefore not exposed to such an attack.


## Build
The executable can be compiled or created inside a docker container. Here the instructions on how to build and run the docker container. Look at the Dockerfile to see how the build is done locally.

Clone this repository and:
```
> docker build --no-cache -t anonymizer -f Dockerfile .
> docker run --rm -it anonymizer
USAGE: anonymize [options]

Options:
--help               Anonymize DICOM images. Read DICOM image series and write
                     out an anonymized version of the files based on the
                     recommendations of the cancer imaging archive.
--input, -i          Input directory.
--output, -o         Output directory.
--patientid, -p      Patient ID after anonymization (default is "hashuid" to
                     hash the existing id).
--projectname, -j    Project name.
--sitename, -s       Site name.
--siteid, -s         Site id.
--dateincrement, -d  Number of days that should be added to dates.
--exportanon, -a     Writes the anonymization structure as a json file to disk
                     and quits the program. There is no way to import a new
                     file currently.
--byseries, -b       Writes each DICOM file into a separate directory by image
                     series.
--storemapping, -m   Store the StudyInstanceUID mapping as a JSON file.
--tagchange, -P      Changes the default behavior for a tag in the build-in
                     rules.
--regtagchange, -R   Changes the default behavior for a tag in the build-in
                     rules (understands regular expressions, retains all
                     capturing groups).
--numthreads, -t     How many threads should be used (default 4).

Examples:
  anonymize --input directory --output directory --patientid bla -d 42 -b
  anonymize --exportanon rules.json
  anonymize --tagchange "0008,0080=PROJECTNAME" --tagchange "0008,0081=bla" \
            --exportanon rules.json
  anonymize --help		
```

We use cmake to build inside the container (debug build):

```
cmake -DCMAKE_BUILD_TYPE=Debug .
```

If you get an error about docbook and xsl/xml processing you may remove the generation of man pages:

```
cmake -DCMAKE_BUILD_TYPE=Debug -DGDCM_BUILD_DOCBOOK_MANPAGES:BOOL=OFF ../GDCM-3.0.20
```

Actually its better to keep the man pages build because they are needed later. If you get the error instead set the following environment variable

```
export XML_CATALOG_FILES="/opt/homebrew/etc/xml/catalog"
```

and 'make'.

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

Our PACS system stores only a single copy per SOPInstanceUID/StudyID - which makes sense. In order to support data that is project
specific I changed the hashing algorithm (hashuid+PROJECTNAME) to include the projects name (-j option) for tags that relate
to image, series, study and frame of reference uids. This generates full copies of the data, one for each project. Deleting
data from one project does not influence the same data used in another project.

Information inside sequences (presentation states) are anonymized as well. This should work as long as the sequence tag is
not listed as "remove". The sequence anonymization function will only check tags at two sequence levels (all tags of a
sequence inside another sequence are anonymized). This has been verified with text label overlays.
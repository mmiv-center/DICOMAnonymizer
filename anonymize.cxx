/*=========================================================================

  Program: Anonymization using gdcm

  Copyright (c) 2019 Hauke Bartsch

  =========================================================================*/
#include "SHA-256.hpp"
#include "dateprocessing.h"
#include "gdcmAnonymizer.h"
#include "gdcmDefs.h"
#include "gdcmDirectory.h"
#include "gdcmFileAnonymizer.h"
#include "gdcmImageReader.h"
#include "gdcmReader.h"
#include "gdcmStringFilter.h"
#include "gdcmSystem.h"
#include "gdcmWriter.h"
#include "json.hpp"
#include "optionparser.h"
#include <gdcmUIDGenerator.h>

#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <exception>
#include <stdexcept>


#include <pthread.h>
#include <stdio.h>
#include <thread>
#include <chrono>

struct threadparams {
  const char **filenames;
  size_t nfiles;
  char *scalarpointer;
  std::string outputdir;
  std::string patientid;
  std::string projectname;
  int dateincrement;
  bool byseries;
  int thread; // number of the thread
};

nlohmann::json work = nlohmann::json::array({
    {"0008", "0050", "AccessionNumber", "hash"},
    {"0018", "4000", "AcquisitionComments", "keep"},
    {"0040", "0555", "AcquisitionContextSeq", "remove"},
    {"0008", "0022", "AcquisitionDate", "incrementdate"},
    {"0008", "002a", "AcquisitionDatetime", "incrementdate"},
    {"0018", "1400", "AcquisitionDeviceProcessingDescription", "keep"},
    {"0018", "9424", "AcquisitionProtocolDescription", "keep"},
    {"0008", "0032", "AcquisitionTime", "keep"},
    {"0040", "4035", "ActualHumanPerformersSequence", "remove"},
    {"0010", "21b0", "AdditionalPatientHistory", "keep"},
    {"0038", "0010", "AdmissionID", "remove"},
    {"0038", "0020", "AdmittingDate", "incrementdate"},
    {"0008", "1084", "AdmittingDiagnosesCodeSeq", "keep"},
    {"0008", "1080", "AdmittingDiagnosesDescription", "keep"},
    {"0038", "0021", "AdmittingTime", "keep"},
    {"0010", "2110", "Allergies", "keep"},
    {"4000", "0010", "Arbitrary", "remove"},
    {"0040", "a078", "AuthorObserverSequence", "remove"},
    {"0013", "0010", "BlockOwner", "CTP"},
    {"0018", "0015", "BodyPartExamined", "BODYPART"},
    {"0010", "1081", "BranchOfService", "remove"},
    {"0028", "0301", "BurnedInAnnotation", "keep"},
    {"0018", "1007", "CassetteID", "keep"},
    {"0040", "0280", "CommentsOnPPS", "keep"},
    {"0020", "9161", "ConcatenationUID", "hashuid"},
    {"0040", "3001", "ConfidentialityPatientData", "remove"},
    {"0070", "0086", "ContentCreatorsIdCodeSeq", "remove"},
    {"0070", "0084", "ContentCreatorsName", "empty"},
    {"0008", "0023", "ContentDate", "incrementdate"},
    {"0040", "a730", "ContentSeq", "remove"},
    {"0008", "0033", "ContentTime", "keep"},
    {"0008", "010d", "ContextGroupExtensionCreatorUID", "hashuid"},
    {"0018", "0010", "ContrastBolusAgent", "keep"},
    {"0018", "a003", "ContributionDescription", "keep"},
    {"0010", "2150", "CountryOfResidence", "remove"},
    {"0008", "9123", "CreatorVersionUID", "hashuid"},
    {"0038", "0300", "CurrentPatientLocation", "remove"},
    {"0008", "0025", "CurveDate", "incrementdate"},
    {"0008", "0035", "CurveTime", "keep"},
    {"0040", "a07c", "CustodialOrganizationSeq", "remove"},
    {"fffc", "fffc", "DataSetTrailingPadding", "remove"},
    {"0018", "1200", "DateofLastCalibration", "incrementdate"},
    {"0018", "700c", "DateofLastDetectorCalibration", "incrementdate"},
    {"0018", "1012", "DateOfSecondaryCapture", "incrementdate"},
    {"0012", "0063",
     "DeIdentificationMethod {Per DICOM PS 3.15 AnnexE. Details in 0012,0064}"},
    {"0012", "0064",
     "DeIdentificationMethodCodeSequence "
     "113100/113101/113105/113107/113108/113109/113111"},
    {"0008", "2111", "DerivationDescription", "keep"},
    {"0018", "700a", "DetectorID", "keep"},
    {"0018", "1000", "DeviceSerialNumber", "keep"},
    {"0018", "1002", "DeviceUID", "keep"},
    {"fffa", "fffa", "DigitalSignaturesSeq", "remove"},
    {"0400", "0100", "DigitalSignatureUID", "remove"},
    {"0020", "9164", "DimensionOrganizationUID", "hashuid"},
    {"0038", "0040", "DischargeDiagnosisDescription", "keep"},
    {"4008", "011a", "DistributionAddress", "remove"},
    {"4008", "0119", "DistributionName", "remove"},
    {"300a", "0013", "DoseReferenceUID", "hashuid"},
    {"0010", "2160", "EthnicGroup", "keep"},
    {"0008", "0058", "FailedSOPInstanceUIDList", "hashuid"},
    {"0070", "031a", "FiducialUID", "hashuid"},
    {"0040", "2017", "FillerOrderNumber", "empty"},
    {"0020", "9158", "FrameComments", "keep"},
    {"0020", "0052", "FrameOfReferenceUID", "hashuid"},
    {"0018", "1008", "GantryID", "keep"},
    {"0018", "1005", "GeneratorID", "keep"},
    {"0070", "0001", "GraphicAnnotationSequence", "remove"},
    {"0040", "4037", "HumanPerformersName", "remove"},
    {"0040", "4036", "HumanPerformersOrganization", "remove"},
    {"0088", "0200", "IconImageSequence", "remove"},
    {"0008", "4000", "IdentifyingComments", "keep"},
    {"0020", "4000", "ImageComments", "keep"},
    {"0028", "4000", "ImagePresentationComments", "remove"},
    {"0040", "2400", "ImagingServiceRequestComments", "keep"},
    {"4008", "0300", "Impressions", "keep"},
    {"0008", "0012", "InstanceCreationDate", "incrementdate"},
    {"0008", "0014", "InstanceCreatorUID", "hashuid"},
    {"0008", "0081", "InstitutionAddress", "remove"},
    {"0008", "1040", "InstitutionalDepartmentName", "remove"},
    {"0008", "0082", "InstitutionCodeSequence", "remove"},
    {"0008", "0080", "InstitutionName", "remove"},
    {"0010", "1050", "InsurancePlanIdentification", "remove"},
    {"0040", "1011", "IntendedRecipientsOfResultsIDSequence", "remove"},
    {"4008", "0111", "InterpretationApproverSequence", "remove"},
    {"4008", "010c", "InterpretationAuthor", "remove"},
    {"4008", "0115", "InterpretationDiagnosisDescription", "keep"},
    {"4008", "0202", "InterpretationIdIssuer", "remove"},
    {"4008", "0102", "InterpretationRecorder", "remove"},
    {"4008", "010b", "InterpretationText", "keep"},
    {"4008", "010a", "InterpretationTranscriber", "remove"},
    {"0008", "3010", "IrradiationEventUID", "hashuid"},
    {"0038", "0011", "IssuerOfAdmissionID", "remove"},
    {"0010", "0021", "IssuerOfPatientID", "remove"},
    {"0038", "0061", "IssuerOfServiceEpisodeId", "remove"},
    {"0028", "1214", "LargePaletteColorLUTUid", "hashuid"},
    {"0010", "21d0", "LastMenstrualDate", "incrementdate"},
    {"0028", "0303", "LongitudinalTemporalInformationModified", "MODIFIED"},
    {"0400", "0404", "MAC", "remove"},
    {"0008", "0070", "Manufacturer", "keep"},
    {"0008", "1090", "ManufacturerModelName", "keep"},
    {"0010", "2000", "MedicalAlerts", "keep"},
    {"0010", "1090", "MedicalRecordLocator", "remove"},
    {"0010", "1080", "MilitaryRank", "remove"},
    {"0400", "0550", "ModifiedAttributesSequence", "remove"},
    {"0020", "3406", "ModifiedImageDescription", "remove"},
    {"0020", "3401", "ModifyingDeviceID", "remove"},
    {"0020", "3404", "ModifyingDeviceManufacturer", "remove"},
    {"0008", "1060", "NameOfPhysicianReadingStudy", "remove"},
    {"0040", "1010", "NamesOfIntendedRecipientsOfResults", "remove"},
    {"0010", "2180", "Occupation", "keep"},
    {"0008", "1070", "OperatorName", "remove"},
    {"0008", "1072", "OperatorsIdentificationSeq", "remove"},
    {"0040", "2010", "OrderCallbackPhoneNumber", "remove"},
    {"0040", "2008", "OrderEnteredBy", "remove"},
    {"0040", "2009", "OrderEntererLocation", "remove"},
    {"0400", "0561", "OriginalAttributesSequence", "remove"},
    {"0010", "1000", "OtherPatientIDs", "remove"},
    {"0010", "1002", "OtherPatientIDsSeq", "remove"},
    {"0010", "1001", "OtherPatientNames", "remove"},
    {"0008", "0024", "OverlayDate", "incrementdate"},
    {"0008", "0034", "OverlayTime", "keep"},
    {"0028", "1199", "PaletteColorLUTUID", "hashuid"},
    {"0040", "a07a", "ParticipantSequence", "remove"},
    {"0010", "1040", "PatientAddress", "remove"},
    {"0010", "1010", "PatientAge", "keep"},
    {"0010", "0030", "PatientBirthDate", "empty"},
    {"0010", "1005", "PatientBirthName", "remove"},
    {"0010", "0032", "PatientBirthTime", "remove"},
    {"0010", "4000", "PatientComments", "keep"},
    {"0010", "0020", "PatientID", "Re-Mapped"},
    {"0012", "0062", "PatientIdentityRemoved", "YES"},
    {"0038", "0400", "PatientInstitutionResidence", "remove"},
    {"0010", "0050", "PatientInsurancePlanCodeSeq", "remove"},
    {"0010", "1060", "PatientMotherBirthName", "remove"},
    {"0010", "0010", "PatientName", "Re-Mapped"},
    {"0010", "2154", "PatientPhoneNumbers", "remove"},
    {"0010", "0101", "PatientPrimaryLanguageCodeSeq", "remove"},
    {"0010", "0102", "PatientPrimaryLanguageModifierCodeSeq", "remove"},
    {"0010", "21f0", "PatientReligiousPreference", "remove"},
    {"0010", "0040", "PatientSex", "keep"},
    {"0010", "2203", "PatientSexNeutered", "keep"},
    {"0010", "1020", "PatientSize", "keep"},
    {"0038", "0500", "PatientState", "keep"},
    {"0040", "1004", "PatientTransportArrangements", "remove"},
    {"0010", "1030", "PatientWeight", "keep"},
    {"0040", "0243", "PerformedLocation", "remove"},
    {"0040", "0241", "PerformedStationAET", "keep"},
    {"0040", "4030", "PerformedStationGeoLocCodeSeq", "keep"},
    {"0040", "0242", "PerformedStationName", "keep"},
    {"0040", "4028", "PerformedStationNameCodeSeq", "keep"},
    {"0008", "1052", "PerformingPhysicianIdSeq", "remove"},
    {"0008", "1050", "PerformingPhysicianName", "remove"},
    {"0040", "0250", "PerformProcedureStepEndDate", "incrementdate"},
    {"0040", "1102", "PersonAddress", "remove"},
    {"0040", "1101", "PersonIdCodeSequence", "remove"},
    {"0040", "a123", "PersonName", "empty"},
    {"0040", "1103", "PersonTelephoneNumbers", "remove"},
    {"4008", "0114", "PhysicianApprovingInterpretation", "remove"},
    {"0008", "1048", "PhysicianOfRecord", "remove"},
    {"0008", "1049", "PhysicianOfRecordIdSeq", "remove"},
    {"0008", "1062", "PhysicianReadingStudyIdSeq", "remove"},
    {"0040", "2016", "PlaceOrderNumberOfImagingServiceReq", "empty"},
    {"0018", "1004", "PlateID", "keep"},
    {"0040", "0254", "PPSDescription", "keep"},
    {"0040", "0253", "PPSID", "remove"},
    {"0040", "0244", "PPSStartDate", "incrementdate"},
    {"0040", "0245", "PPSStartTime", "keep"},
    {"0010", "21c0", "PregnancyStatus", "keep"},
    {"0040", "0012", "PreMedication", "keep"},
    {"0013", "1010", "ProjectName", "always"},
    {"0018", "1030", "ProtocolName", "keep"},
    {"0054", "0016", "Radiopharmaceutical Information Sequence process"},
    {"0018", "1078", "Radiopharmaceutical Start DateTime", "incrementdate"},
    {"0018", "1079", "Radiopharmaceutical Stop DateTime", "incrementdate"},
    {"0040", "2001", "ReasonForImagingServiceRequest", "keep"},
    {"0032", "1030", "ReasonforStudy", "keep"},
    {"0400", "0402", "RefDigitalSignatureSeq", "remove"},
    {"3006", "0024", "ReferencedFrameOfReferenceUID", "hashuid"},
    {"0038", "0004", "ReferencedPatientAliasSeq", "remove"},
    {"0008", "0092", "ReferringPhysicianAddress", "remove"},
    {"0008", "0090", "ReferringPhysicianName", "empty"},
    {"0008", "0094", "ReferringPhysicianPhoneNumbers", "remove"},
    {"0008", "0096", "ReferringPhysiciansIDSeq", "remove"},
    {"0040", "4023", "RefGenPurposeSchedProcStepTransUID", "hashuid"},
    {"0008", "1140", "RefImageSeq", "remove"},
    {"0008", "1120", "RefPatientSeq", "remove"},
    {"0008", "1111", "RefPPSSeq", "remove"},
    {"0008", "1150", "RefSOPClassUID", "keep"},
    {"0400", "0403", "RefSOPInstanceMACSeq", "remove"},
    {"0008", "1155", "RefSOPInstanceUID", "hashuid"},
    {"0008", "1110", "RefStudySeq", "remove"},
    {"0010", "2152", "RegionOfResidence", "remove"},
    {"3006", "00c2", "RelatedFrameOfReferenceUID", "hashuid"},
    {"0040", "0275", "RequestAttributesSeq", "remove"},
    {"0032", "1070", "RequestedContrastAgent", "keep"},
    {"0040", "1400", "RequestedProcedureComments", "keep"},
    {"0032", "1060", "RequestedProcedureDescription", "keep"},
    {"0040", "1001", "RequestedProcedureID", "remove"},
    {"0040", "1005", "RequestedProcedureLocation", "remove"},
    {"0032", "1032", "RequestingPhysician", "remove"},
    {"0032", "1033", "RequestingService", "remove"},
    {"0010", "2299", "ResponsibleOrganization", "remove"},
    {"0010", "2297", "ResponsiblePerson", "remove"},
    {"4008", "4000", "ResultComments", "keep"},
    {"4008", "0118", "ResultsDistributionListSeq", "remove"},
    {"4008", "0042", "ResultsIDIssuer", "remove"},
    {"300e", "0008", "ReviewerName", "remove"},
    {"0040", "4034", "ScheduledHumanPerformersSeq", "remove"},
    {"0038", "001e", "ScheduledPatientInstitutionResidence", "remove"},
    {"0040", "000b", "ScheduledPerformingPhysicianIDSeq", "remove"},
    {"0040", "0006", "ScheduledPerformingPhysicianName", "remove"},
    {"0040", "0001", "ScheduledStationAET", "keep"},
    {"0040", "4027", "ScheduledStationGeographicLocCodeSeq", "keep"},
    {"0040", "0010", "ScheduledStationName", "keep"},
    {"0040", "4025", "ScheduledStationNameCodeSeq", "keep"},
    {"0032", "1020", "ScheduledStudyLocation", "keep"},
    {"0032", "1021", "ScheduledStudyLocationAET", "keep"},
    {"0032", "1000", "ScheduledStudyStartDate", "incrementdate"},
    {"0008", "0021", "SeriesDate", "incrementdate"},
    {"0008", "103e", "SeriesDescription", "keep"},
    {"0020", "000e", "SeriesInstanceUID", "hashuid"},
    {"0008", "0031", "SeriesTime", "keep"},
    {"0038", "0062", "ServiceEpisodeDescription", "keep"},
    {"0038", "0060", "ServiceEpisodeID", "remove"},
    {"0013", "1013", "SiteID", "SITEID"},
    {"0013", "1012", "SiteName", "SITENAME"},
    {"0010", "21a0", "SmokingStatus", "keep"},
    {"0018", "1020", "SoftwareVersion", "keep"},
    {"0008", "0018", "SOPInstanceUID", "hashuid"},
    {"0008", "2112", "SourceImageSeq", "remove"},
    {"0038", "0050", "SpecialNeeds", "keep"},
    {"0040", "0007", "SPSDescription", "keep"},
    {"0040", "0004", "SPSEndDate", "incrementdate"},
    {"0040", "0005", "SPSEndTime", "keep"},
    {"0040", "0011", "SPSLocation", "keep"},
    {"0040", "0002", "SPSStartDate", "incrementdate"},
    {"0040", "0003", "SPSStartTime", "keep"},
    {"0008", "1010", "StationName", "remove"},
    {"0088", "0140", "StorageMediaFilesetUID", "hashuid"},
    {"3006", "0008", "StructureSetDate", "incrementdate"},
    {"0032", "1040", "StudyArrivalDate", "incrementdate"},
    {"0032", "4000", "StudyComments", "keep"},
    {"0032", "1050", "StudyCompletionDate", "incrementdate"},
    {"0008", "0020", "StudyDate", "incrementdate"},
    {"0008", "1030", "StudyDescription", "keep"},
    {"0020", "0010", "StudyID", "empty"},
    {"0032", "0012", "StudyIDIssuer", "remove"},
    {"0020", "000d", "StudyInstanceUID", "hashuid"},
    {"0008", "0030", "StudyTime", "keep"},
    {"0020", "0200", "SynchronizationFrameOfReferenceUID", "hashuid"},
    {"0040", "db0d", "TemplateExtensionCreatorUID", "hashuid"},
    {"0040", "db0c", "TemplateExtensionOrganizationUID", "hashuid"},
    {"4000", "4000", "TextComments", "remove"},
    {"2030", "0020", "TextString", "remove"},
    {"0008", "0201", "TimezoneOffsetFromUTC", "remove"},
    {"0088", "0910", "TopicAuthor", "remove"},
    {"0088", "0912", "TopicKeyWords", "remove"},
    {"0088", "0906", "TopicSubject", "remove"},
    {"0088", "0904", "TopicTitle", "remove"},
    {"0008", "1195", "TransactionUID", "hashuid"},
    {"0013", "1011", "TrialName", "PROJECTNAME"},
    {"0040", "a124", "UID", "hashuid"},
    {"0040", "a088", "VerifyingObserverIdentificationCodeSeq", "remove"},
    {"0040", "a075", "VerifyingObserverName", "empty"},
    {"0040", "a073", "VerifyingObserverSequence", "remove"},
    {"0040", "a027", "VerifyingOrganization", "remove"},
    {"0038", "4000", "VisitComments", "keep"},
});

void *ReadFilesThread(void *voidparams) {
  const threadparams *params = static_cast<const threadparams *>(voidparams);

  const size_t nfiles = params->nfiles;
  for (unsigned int file = 0; file < nfiles; ++file) {
    const char *filename = params->filenames[file];
    // std::cerr << filename << std::endl;

    gdcm::ImageReader reader;
    reader.SetFileName(filename);
    try {
      if (!reader.Read()) {
        std::cerr << "Failed to read: \"" << filename << "\" in thread " << params->thread << std::endl;
        // lets try again
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!reader.Read())
        {
          std::cerr << "Failed second time to read: \"" << filename << "\" in thread " << params->thread << std::endl;
          continue;
        }
      }
    }
    catch (...)
    {
      std::cerr << "Failed to read: \"" << filename << "\" in thread " << params->thread << std::endl;
      continue;
    }

    const gdcm::Image &image = reader.GetImage();
    // if we have the image here we can anonymize now and write again
    gdcm::Anonymizer anon;
    gdcm::File &fileToAnon = reader.GetFile();
    anon.SetFile(fileToAnon);

    gdcm::MediaStorage ms;
    ms.SetFromFile(fileToAnon);
    if (!gdcm::Defs::GetIODNameFromMediaStorage(ms)) {
      std::cerr << "The Media Storage Type of your file is not supported: "
                << ms << std::endl;
      std::cerr << "Please report" << std::endl;
      continue;
    }
    gdcm::DataSet &ds = fileToAnon.GetDataSet();

    gdcm::StringFilter sf;
    sf.SetFile(fileToAnon);

    // use the following tags
    // https://wiki.cancerimagingarchive.net/display/Public/De-identification+Knowledge+Base

    /*    Tag    Name    Action */

    std::string filenamestring = "";
    std::string seriesdirname = ""; // only used if byseries is true

    // now walk through the list of entries and apply each one
    for (int i = 0; i < work.size(); i++) {
      // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
      std::string tag1(work[i][0]);
      std::string tag2(work[i][1]);
      std::string which(work[i][2]);
      std::string what("replace");
      if (work[i].size() > 3) {
        what = work[i][3];
      }
      int a = strtol(tag1.c_str(), NULL, 16);
      int b = strtol(tag2.c_str(), NULL, 16);
      // fprintf(stdout, "Tag: %s %04X %04X\n", which.c_str(), a, b);
      if (which == "BlockOwner" && what != "replace") {
        anon.Replace(gdcm::Tag(a, b), what.c_str());
      }
      if (which == "ProjectName") {
        anon.Replace(gdcm::Tag(a, b), params->projectname.c_str());
      }
      if (what == "replace")
        anon.Replace(gdcm::Tag(a, b), which.c_str());
      if (what == "remove")
        anon.Remove(gdcm::Tag(a, b));
      if (what == "empty")
        anon.Replace(gdcm::Tag(a, b), "");
      if (what == "hashuid") {
        std::string val = sf.ToString(gdcm::Tag(a, b));
        std::string hash = SHA256::digestString(val).toHex();
        if (which == "SOPInstanceUID") // keep a copy as the filename for the output
          filenamestring = hash.c_str();

        if (which == "SeriesInstanceUID")
          seriesdirname = hash.c_str();

        anon.Replace(gdcm::Tag(a, b), hash.c_str());
      }
      if (what == "keep") {
        // so we do nothing...
      }
      if (what == "incrementdate") {
        int nd = params->dateincrement;
        std::string val = sf.ToString(gdcm::Tag(a, b));
        // parse the date string YYYYMMDD
        struct sdate date1;
        if (sscanf(val.c_str(), "%04ld%02ld%02ld", &date1.y, &date1.m,
                   &date1.d) == 3) {
          // replace with added value
          long c = gday(date1) + nd;
          struct sdate date2 = dtf(c);
          char dat[256];
          sprintf(dat, "%04ld%02ld%02ld", date2.y, date2.m, date2.d);
          // fprintf(stdout, "found a date : %s, replace with date: %s\n",
          // val.c_str(), dat);

          anon.Replace(gdcm::Tag(a, b), dat);
        } else {
          // could not read the date here, just remove instead
          // fprintf(stdout, "Warning: could not parse a date (\"%s\", %04o,
          // %04o, %s) in %s, remove field instead...\n", val.c_str(), a, b,
          // which.c_str(), filename);
          anon.Replace(gdcm::Tag(a, b), "");
        }
      }
    }
    anon.Replace(gdcm::Tag(0x0010, 0x0010),
                 params->patientid.c_str()); // this is re-mapped
    anon.Replace(gdcm::Tag(0x0010, 0x0020), params->patientid.c_str());

    // ok save the file again
    std::string imageInstanceUID = filenamestring;
    if (imageInstanceUID == "") {
      fprintf(stderr, "Error: cannot read image instance uid from %s\n",
              filename);
      gdcm::UIDGenerator gen;
      imageInstanceUID = gen.Generate();
    }
    std::string fn = params->outputdir + "/" + filenamestring + ".dcm";
		if (params->byseries) {
			// use the series instance uid as a directory name
			std::string dn = params->outputdir + "/" + seriesdirname;
			DIR *dir = opendir(dn.c_str());
			if ( ENOENT == errno)	{
				mkdir(dn.c_str(), 0700);
			} else {
        closedir(dir);
      }
      fn = params->outputdir + "/" + seriesdirname + "/" + filenamestring + ".dcm";
		}

		fprintf(stdout, "[%d] write to file: %s\n", params->thread, fn.c_str());
    std::string outfilename(fn);

    // save the file again to the output
    gdcm::Writer writer;
    writer.SetFile(fileToAnon);

    gdcm::Trace::SetDebug( true );
    gdcm::Trace::SetWarning( true );
    writer.SetFileName(outfilename.c_str());
    try {
      if (!writer.Write()) {
        fprintf(stderr, "Error [%d, %d] writing file \"%s\" to \"%s\".\n", file, params->thread, filename, outfilename.c_str());
        fprintf(stderr, "ERROR: %s\n", gdcm::System::GetLastSystemError());
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!writer.Write()) {
          fprintf(stderr, "Error second time [%d, %d] writing file \"%s\" to \"%s\".\n", file, params->thread, filename, outfilename.c_str());
          fprintf(stderr, "ERROR (second time): %s\n", gdcm::System::GetLastSystemError());
        }
      }
    } catch (const std::exception &ex) {
      std::cout << "Caught exception \"" << ex.what() << "\"\n";
    }
  }
  return voidparams;
}

void ShowFilenames(const threadparams &params) {
  std::cout << "start" << std::endl;
  for (unsigned int i = 0; i < params.nfiles; ++i) {
    const char *filename = params.filenames[i];
    std::cout << filename << std::endl;
  }
  std::cout << "end" << std::endl;
}

void ReadFiles(size_t nfiles, const char *filenames[], const char *outputdir,
               const char *patientid, int dateincrement, bool byseries, int numthreads,
               const char *projectname) {
  // \precondition: nfiles > 0
  assert(nfiles > 0);
/*  const char *reference = filenames[0]; // take the first image as reference

  gdcm::ImageReader reader;
  reader.SetFileName(reference);
  if (!reader.Read()) {
    // That would be very bad...
    assert(0);
  }

  const gdcm::Image &image = reader.GetImage();
  gdcm::PixelFormat pixeltype = image.GetPixelFormat();
  unsigned long len = image.GetBufferLength();
  const unsigned int *dims = image.GetDimensions();
  unsigned short pixelsize = pixeltype.GetPixelSize();
  (void)pixelsize;
  assert(image.GetNumberOfDimensions() == 2); */

  const unsigned int nthreads = numthreads; // how many do we want to use?
  threadparams params[nthreads];

  pthread_t *pthread = new pthread_t[nthreads];

  // There is nfiles, and nThreads
  assert(nfiles > nthreads);
  const size_t partition = nfiles / nthreads;
  for (unsigned int thread = 0; thread < nthreads; ++thread) {
    params[thread].filenames = filenames + thread * partition;
    params[thread].outputdir = outputdir;
    params[thread].patientid = patientid;
    params[thread].nfiles = partition;
    params[thread].dateincrement = dateincrement;
    params[thread].byseries  = byseries;
    params[thread].thread    = thread;
    params[thread].projectname = projectname;
    if (thread == nthreads - 1)
    {
      // There is slightly more files to process in this thread:
      params[thread].nfiles += nfiles % nthreads;
    }
    assert(thread * partition < nfiles);
    int res = pthread_create(&pthread[thread], NULL, ReadFilesThread,
                             &params[thread]);
    if (res) {
      std::cerr << "Unable to start a new thread, pthread returned: " << res
                << std::endl;
      assert(0);
    }
  }
  // DEBUG
  size_t total = 0;
  for (unsigned int thread = 0; thread < nthreads; ++thread) {
    total += params[thread].nfiles;
  }
  assert(total == nfiles);
  // END DEBUG

  for (unsigned int thread = 0; thread < nthreads; thread++) {
    pthread_join(pthread[thread], NULL);
  }
  delete[] pthread;
}

struct Arg : public option::Arg {
  static option::ArgStatus Required(const option::Option &option, bool) {
    return option.arg == 0 ? option::ARG_ILLEGAL : option::ARG_OK;
  }
  static option::ArgStatus Empty(const option::Option &option, bool) {
    return (option.arg == 0 || option.arg[0] == 0) ? option::ARG_OK
                                                   : option::ARG_IGNORE;
  }
};

enum optionIndex {
  UNKNOWN,
  HELP,
  INPUT,
  OUTPUT,
  PATIENTID,
  PROJECTNAME,
  DATEINCREMENT,
  EXPORTANON,
  BYSERIES,
  NUMTHREADS
};
const option::Descriptor usage[] = {
    {UNKNOWN, 0, "", "", option::Arg::None,
     "USAGE: anonymize [options]\n\n"
     "Options:"},
    {HELP, 0, "", "help", Arg::None,
     "  --help  \tAnonymize DICOM images. Read DICOM image series and write "
     "out an anonymized version of the files based on the recommendations of "
     "the cancer imaging archive."},
    {INPUT, 0, "i", "input", Arg::Required,
     "  --input, -i  \tInput directory."},
    {OUTPUT, 0, "o", "output", Arg::Required,
     "  --output, -o  \tOutput directory."},
    {PATIENTID, 0, "p", "patientid", Arg::Required,
     "  --patientid, -p  \tPatient ID after anonymization."},
    {PROJECTNAME, 0, "j", "projectname", Arg::Required,
     "  --projectname, -j  \tProject name."},
    {DATEINCREMENT, 0, "d", "dateincrement", Arg::Required,
     "  --dateincrement, -d  \tNumber of days that should be added to dates."},
    {EXPORTANON, 0, "a", "exportanon", Arg::Required,
     "  --exportanon, -a  \tWrites the anonymization structure as a json file "
     "to disk and quits the program. There is no way to import a new file currently."},
    {BYSERIES, 0, "b", "byseries", Arg::None,
     "  --byseries, -b  \tWrites each DICOM file into a separate directory "
     "by image series."},
    {NUMTHREADS, 0, "t", "numthreads", Arg::Required,
     "  --numthreads, -t  \tHow many threads should be used (default 4)." },
    {UNKNOWN, 0, "", "", Arg::None,
     "\nExamples:\n"
     "  anonymize --input directory --output directory --patientid bla -d 42 -b\n"
     "  anonymize --help\n"},
    {0, 0, 0, 0, 0, 0}};

int main(int argc, char *argv[]) {

  argc -= (argc > 0);
  argv += (argc > 0); // skip program name argv[0] if present

  option::Stats stats(usage, argc, argv);
  std::vector<option::Option> options(stats.options_max);
  std::vector<option::Option> buffer(stats.buffer_max);
  option::Parser parse(usage, argc, argv, &options[0], &buffer[0]);

  if (parse.error())
    return 1;

  if (options[HELP] || argc == 0) {
    option::printUsage(std::cout, usage);
    return 0;
  }

  for (option::Option *opt = options[UNKNOWN]; opt; opt = opt->next())
    std::cout << "Unknown option: " << std::string(opt->name, opt->namelen)
              << "\n";

  std::string input;
  std::string output;
  std::string patientID = "";
  int dateincrement = 42;
  std::string exportanonfilename = ""; // anon.json
  bool byseries = false;
  int numthreads = 4;
  std::string projectname = "";
  for (int i = 0; i < parse.optionsCount(); ++i) {
    option::Option &opt = buffer[i];
    // fprintf(stdout, "Argument #%d is ", i);
    switch (opt.index()) {
    case HELP:
      // not possible, because handled further above and exits the program
    case INPUT:
      if (opt.arg) {
        fprintf(stdout, "--input '%s'\n", opt.arg);
        input = opt.arg;
      } else {
        fprintf(stdout, "--input needs a directory specified\n");
        exit(-1);
      }
      break;
    case OUTPUT:
      if (opt.arg) {
        fprintf(stdout, "--output '%s'\n", opt.arg);
        output = opt.arg;
      } else {
        fprintf(stdout, "--output needs a directory specified\n");
        exit(-1);
      }
      break;
    case PATIENTID:
      if (opt.arg) {
        fprintf(stdout, "--patientid '%s'\n", opt.arg);
        patientID = opt.arg;
      } else {
        fprintf(stdout, "--patientid needs a string specified\n");
        exit(-1);
      }
      break;
    case PROJECTNAME:
      if (opt.arg) {
        fprintf(stdout, "--projectname '%s'\n", opt.arg);
        projectname = opt.arg;
      } else {
        fprintf(stdout, "--projectname needs a string specified\n");
        exit(-1);
      }
      break;
    case DATEINCREMENT:
      if (opt.arg) {
        fprintf(stdout, "--dateincrement %d\n", atoi(opt.arg));
        dateincrement = atoi(opt.arg);
      } else {
        fprintf(stdout, "--dateincrement needs an integer specified\n");
        exit(-1);
      }
      break;
    case BYSERIES:
      fprintf(stdout, "--byseries\n");
      byseries = true;
      break;
    case NUMTHREADS:
      if (opt.arg) {
        fprintf(stdout, "--numthreads %d\n", atoi(opt.arg));
        numthreads = atoi(opt.arg);
      } else {
        fprintf(stdout, "--numthreads needs an integer specified\n");
        exit(-1);
      }
      break;
    case EXPORTANON:
      if (opt.arg) {
        fprintf(stdout, "--exportanon %s\n", opt.arg);
        exportanonfilename = opt.arg;

        // if we need to export the json file, do that and quit
        if (exportanonfilename.length() > 0) {
          fprintf(stdout,
                  "Write the anonymization tag information as a file to disk "
                  "and exit (\"%s\").\n",
                  exportanonfilename.c_str());
          std::ofstream jsonfile(exportanonfilename);
          jsonfile << work;
          jsonfile.flush();
          exit(0);
        }
      } else {
        fprintf(stdout, "--exportanon needs a filename\n");
        exit(-1);
      }
      break;
    case UNKNOWN:
      // not possible because Arg::Unknown returns ARG_ILLEGAL
      // which aborts the parse with an error
      break;
    }
  }

  // Check if user pass in a single directory
  if (gdcm::System::FileIsDirectory(input.c_str())) {
    gdcm::Directory d;
    d.Load(argv[1]);
    gdcm::Directory::FilenamesType l = d.GetFilenames();
    const size_t nfiles = l.size();
    unsigned int chunkSize = 30000; // that many images in one go
    int currentChunk = 0;
    const char **filenames = new const char *[chunkSize];
    int filesInChunk = 0;
    unsigned int idx = 0;
    for (unsigned int i = 0; i < nfiles; ++i) {
      if (i >= (currentChunk * chunkSize)) { // change to the next chunk
        if (filesInChunk > 0) {
          fprintf(stdout, "Send for ReadFiles %d files.\n", filesInChunk);
          ReadFiles(filesInChunk, filenames, output.c_str(), patientID.c_str(),
                    dateincrement, byseries, numthreads, projectname.c_str());
        }
        currentChunk++;
        filesInChunk = 0; // reset
      }
      idx = i - ((currentChunk-1) * chunkSize);
      filesInChunk++;
      fprintf(stdout, "in loop: %d, chunk: %d, total: %ld\n", i, currentChunk, nfiles);
      filenames[idx] = l[i].c_str();
    }
    // do all the left-over once
    fprintf(stdout, "Send left overs to ReadFiles %d files.\n", filesInChunk);
    ReadFiles(filesInChunk, filenames, output.c_str(), patientID.c_str(),
              dateincrement, byseries, numthreads, projectname.c_str());
    delete[] filenames;
  } /* else {
// Simply copy all filenames into the vector:
const char **filenames = const_cast<const char**>(argv+1);
const size_t nfiles = argc - 1;
ReadFiles(nfiles, filenames);
} */

  return 0;
}

/*=========================================================================

  Program: Anonymization using gdcm

  Copyright (c) 2019 Hauke Bartsch

  For debugging use:
    cmake -DCMAKE_BUILD_TYPE=Release ..
  to build gdcm.

//  DumpSiemensBase64.cxx - add CSA header information

  =========================================================================*/
#include "SHA-256.hpp"
#include "dateprocessing.h"
#include "gdcmAnonymizer.h"
#include "gdcmAttribute.h"
#include "gdcmDefs.h"
#include "gdcmDirectory.h"
#include "gdcmGlobal.h"
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
#include <exception>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>

#include <chrono>
#include <map>
#include <pthread.h>
#include <stdio.h>
#include <thread>
#include <regex>

struct threadparams {
  const char **filenames;
  size_t nfiles;
  char *scalarpointer;
  std::string outputdir;
  std::string patientid;
  std::string projectname;
  std::string sitename;
  std::string siteid;
  int dateincrement;
  bool byseries;
  int thread; // number of the thread
  // each thread will store here the study instance uid (original and mapped)
  std::map<std::string, std::string> byThreadStudyInstanceUID;
  std::map<std::string, std::string> byThreadSeriesInstanceUID;
};

// https://wiki.cancerimagingarchive.net/display/Public/De-identification+Knowledge+Base
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
    {"0012", "0063", "DeIdentificationMethod {Per DICOM PS 3.15 AnnexE. Details in 0012,0064}"},
    {"0012", "0064", "DeIdentificationMethodCodeSequence", "113100/113101/113105/113107/113108/113109/113111"},
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
    {"0020", "0052", "FrameOfReferenceUID", "hashuid+PROJECTNAME"},
    {"0018", "1008", "GantryID", "keep"},
    {"0018", "1005", "GeneratorID", "keep"},
    //{"0070", "0001", "GraphicAnnotationSequence", "remove"},
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
    {"0054", "0016", "Radiopharmaceutical Information Sequence", "process"},
    {"0018", "1078", "Radiopharmaceutical Start DateTime", "incrementdate"},
    {"0018", "1079", "Radiopharmaceutical Stop DateTime", "incrementdate"},
    {"0040", "2001", "ReasonForImagingServiceRequest", "keep"},
    {"0032", "1030", "ReasonforStudy", "keep"},
    {"0400", "0402", "RefDigitalSignatureSeq", "remove"},
    {"3006", "0024", "ReferencedFrameOfReferenceUID", "hashuid+PROJECTNAME"},
    {"0038", "0004", "ReferencedPatientAliasSeq", "remove"},
    {"0008", "0092", "ReferringPhysicianAddress", "remove"},
    {"0008", "0090", "ReferringPhysicianName", "empty"},
    {"0008", "0094", "ReferringPhysicianPhoneNumbers", "remove"},
    {"0008", "0096", "ReferringPhysiciansIDSeq", "remove"},
    {"0040", "4023", "RefGenPurposeSchedProcStepTransUID", "hashuid"},
    //{"0008", "1140", "RefImageSeq", "remove"},
    {"0008", "1120", "RefPatientSeq", "remove"},
    {"0008", "1111", "RefPPSSeq", "remove"},
    {"0008", "1150", "RefSOPClassUID", "keep"},
    {"0400", "0403", "RefSOPInstanceMACSeq", "remove"},
    {"0008", "1155", "RefSOPInstanceUID", "hashuid+PROJECTNAME"},
    //{"0008", "1110", "RefStudySeq", "remove"},
    {"0010", "2152", "RegionOfResidence", "remove"},
    {"3006", "00c2", "RelatedFrameOfReferenceUID", "hashuid+PROJECTNAME"},
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
    {"0020", "000e", "SeriesInstanceUID", "hashuid+PROJECTNAME"},
    {"0008", "0031", "SeriesTime", "keep"},
    {"0038", "0062", "ServiceEpisodeDescription", "keep"},
    {"0038", "0060", "ServiceEpisodeID", "remove"},
    {"0013", "1013", "SiteID", "SITEID"},
    {"0013", "1012", "SiteName", "SITENAME"},
    {"0010", "21a0", "SmokingStatus", "keep"},
    {"0018", "1020", "SoftwareVersion", "keep"},
    {"0008", "0018", "SOPInstanceUID", "hashuid+PROJECTNAME"},
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
    {"0020", "000d", "StudyInstanceUID", "hashuid+PROJECTNAME"},
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

// anonymizes only two levels in a sequence
void anonymizeSequence(threadparams *params, gdcm::DataSet *dss, gdcm::Tag *tsqur) {
  gdcm::DataElement squr = dss->GetDataElement(*tsqur);
  // gdcm::DataElement squr = *squrP;
  gdcm::SequenceOfItems *sqi = squr.GetValueAsSQ();
  if (!sqi || !sqi->GetNumberOfItems()) {
    // fprintf(stdout, "this is not a sequence... don't handle as sequence\n");
    return; // do not continue here
  }
  // lets do the anonymization twice, once on the lowest level and once on the level above
  // sequences lowest level
  for (int itemIdx = 1; itemIdx <= sqi->GetNumberOfItems(); itemIdx++) {
    // normally we only find a single item here, could be more
    gdcm::Item &item = sqi->GetItem(itemIdx);
    gdcm::DataSet &nestedds = item.GetNestedDataSet();

    // we should go through each DataElement of this DataSet
    gdcm::DataSet::Iterator it = nestedds.Begin();
    for (; it != nestedds.End();) {
      const gdcm::DataElement &de = *it;
      gdcm::Tag tt = de.GetTag();

      // maybe this is a sequence?
      bool isSequence = false;
      gdcm::SmartPointer<gdcm::SequenceOfItems> seq = de.GetValueAsSQ();
      if (seq && seq->GetNumberOfItems()) {
        isSequence = true;
      }

      if (!isSequence) {
        // fprintf(stdout, "in itemIdx %04x,%04x this is not a sequence\n", tt.GetGroup(), tt.GetElement());

        // what type of tag do we have? if its a sequence go through it, if not check if we have to anonymize this tag
        for (int wi = 0; wi < work.size(); wi++) {
          // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
          std::string tag1(work[wi][0]);
          std::string tag2(work[wi][1]);
          std::string which(work[wi][2]);
          std::string what("replace");
	  bool regexp = false; // if we find a regular expression, only retain the entries that are capturing groups (separated by a space)
          if (work[wi].size() > 3) {
            what = work[wi][3];
          }
	  if (work[wi].size() > 4 && work[wi][4] == "regexp") {
	    regexp = true;
	  }
          if (what != "hashuid+PROJECTNAME")
            continue; // we can only do this inside a sequence, would be good if we can do more inside sequences!!!!
          int a = strtol(tag1.c_str(), NULL, 16);
          int b = strtol(tag2.c_str(), NULL, 16);
          gdcm::Tag aa(a, b); // now works
          if (tt.GetGroup() != a || tt.GetElement() != b) {
            continue;
          }
          // fprintf(stdout, "Found a tag: %s, %s\n", tag1.c_str(), tag2.c_str());

          gdcm::DataElement cm = de;
          const gdcm::ByteValue *bv = cm.GetByteValue();
	  if (bv != NULL) {
	    std::string dup(bv->GetPointer(), bv->GetLength());
	    std::string hash = SHA256::digestString(dup + params->projectname).toHex();
	    // fprintf(stdout, "replace one value!!!! %s\n", hash.c_str());
	    cm.SetByteValue(hash.c_str(), (uint32_t)hash.size());
	    // cm.SetVLToUndefined();
	    // cm.SetVR(gdcm::VR::UI); // valid for ReferencedSOPInstanceUID
	    nestedds.Replace(cm);
	    // fprintf(stdout, "REPLACED ONE VALUE at %d -> %04x,%04x\n", wi, aa.GetGroup(), aa.GetElement());
	  }
        }
      } else { // we have a sequence, lets go in and change all values
        // make a copy of the whole thing and set to VL undefined
        gdcm::DataElement ppp2 = de;
        ppp2.SetVLToUndefined();
        gdcm::SmartPointer<gdcm::SequenceOfItems> seq = ppp2.GetValueAsSQ();
        if (seq && seq->GetNumberOfItems()) {
          for (int i = 1; i <= seq->GetNumberOfItems(); i++) {
            gdcm::Item &item2 = seq->GetItem(i);
            gdcm::DataSet &nestedds2 = item2.GetNestedDataSet();

            // inside this sequence we could have tags that we need to anonymize, check all and fidn out if one needs our attention
            for (int wi = 0; wi < work.size(); wi++) {
              // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
              std::string tag1(work[wi][0]);
              std::string tag2(work[wi][1]);
              std::string which(work[wi][2]);
              std::string what("replace");
              if (work[wi].size() > 3) {
                what = work[wi][3];
              }
              if (what != "hashuid+PROJECTNAME")
                continue; // we can only do this inside a sequence
              int a = strtol(tag1.c_str(), NULL, 16);
              int b = strtol(tag2.c_str(), NULL, 16);
              gdcm::Tag aa(a, b); // now works

              // REPLACE
              // gdcm::Tag tcm(0x0008,0x1155);
              if (nestedds2.FindDataElement(aa)) {
                // fprintf(stdout, "Found a tag: %s, %s\n", tag1.c_str(), tag2.c_str());
                gdcm::DataElement cm = nestedds2.GetDataElement(aa);
                const gdcm::ByteValue *bv = cm.GetByteValue();
		if (bv != NULL) {
		  std::string dup(bv->GetPointer(), bv->GetLength());
		  std::string hash = SHA256::digestString(dup + params->projectname).toHex();
		  // fprintf(stdout, "replace one value!!!! %s\n", hash.c_str());
		  cm.SetByteValue(hash.c_str(), (uint32_t)hash.size());
		  // cm.SetVLToUndefined();
		  // cm.SetVR(gdcm::VR::UI);
		  // valid for ReferencedSOPInstanceUID
		  nestedds2.Replace(cm);
		}		   
              }
              // END REPLACE
            }
          }
          nestedds.Replace(ppp2);
        }
      }

      ++it;
    }

    // how to anonymize a tag at this level
    /*    gdcm::Tag siuid(0x0020,0x000e);
    if (nestedds.FindDataElement(siuid)) {
      gdcm::DataElement cm = nestedds.GetDataElement( siuid );
      const gdcm::ByteValue *bv = cm.GetByteValue();
      std::string dup( bv->GetPointer(), bv->GetLength() );
      std::string hash = SHA256::digestString(dup+params->projectname).toHex();
      //fprintf(stdout, "replace one value!!!! %s\n", hash.c_str());
      cm.SetByteValue( hash.c_str(), (uint32_t)hash.size() );
      //cm.SetVLToUndefined();
      //cm.SetVR(gdcm::VR::UI); // valid for ReferencedSOPInstanceUID
      nestedds.Replace( cm );
      } */

    // how to anonymize a sequence at this level
    /*    gdcm::Tag purpose(0x0008,0x1140);
    if (nestedds.FindDataElement( purpose )) {
      const gdcm::DataElement &ppp = nestedds.GetDataElement( purpose );
      // make a copy of the whole thing and set to VL undefined
      gdcm::DataElement ppp2 = ppp;
      ppp2.SetVLToUndefined();
      gdcm::SmartPointer<gdcm::SequenceOfItems> seq = ppp2.GetValueAsSQ();
      if (seq && seq->GetNumberOfItems() ) {
  for (int i = 1; i <= seq->GetNumberOfItems(); i++ ) {
    gdcm::Item &item2 = seq->GetItem(i);
    gdcm::DataSet &nestedds2 = item2.GetNestedDataSet();

    gdcm::Tag tcm(0x0008,0x1155);
    if (nestedds2.FindDataElement(tcm)) {
      gdcm::DataElement cm = nestedds2.GetDataElement( tcm );
      const gdcm::ByteValue *bv = cm.GetByteValue();
      std::string dup( bv->GetPointer(), bv->GetLength() );
      std::string hash = SHA256::digestString(dup+params->projectname).toHex();
      // fprintf(stdout, "replace one value!!!! %s\n", hash.c_str());
      cm.SetByteValue( hash.c_str(), (uint32_t)hash.size() );
      //cm.SetVLToUndefined();
      //cm.SetVR(gdcm::VR::UI); // valid for ReferencedSOPInstanceUID
      nestedds2.Replace( cm );
    }
  }
  nestedds.Replace(ppp2);
      }
      } */
  }

  gdcm::DataElement squr_dup = squr;
  squr_dup.SetValue(*sqi);
  squr_dup.SetVLToUndefined();
  dss->Replace(squr_dup);
  return;
}

void *ReadFilesThread(void *voidparams) {
  threadparams *params = static_cast<threadparams *>(voidparams);

  const size_t nfiles = params->nfiles;
  for (unsigned int file = 0; file < nfiles; ++file) {
    const char *filename = params->filenames[file];
    // std::cerr << filename << std::endl;

    // gdcm::ImageReader reader;
    gdcm::Reader reader;
    reader.SetFileName(filename);
    try {
      if (!reader.Read()) {
        std::cerr << "Failed to read: \"" << filename << "\" in thread " << params->thread << std::endl;
      }
    } catch (...) {
      std::cerr << "Failed to read: \"" << filename << "\" in thread " << params->thread << std::endl;
      continue;
    }

    // process sequences as well
    // lets check if we can change the sequence that contains the ReferencedSOPInstanceUID inside the 0008,1115 sequence

    gdcm::DataSet &dss = reader.GetFile().GetDataSet();
    // look for any sequences and process them
    gdcm::DataSet::Iterator it = dss.Begin();
    for (; it != dss.End();) {
      const gdcm::DataElement &de = *it;
      gdcm::Tag tt = de.GetTag();
      gdcm::SmartPointer<gdcm::SequenceOfItems> seq = de.GetValueAsSQ();
      if (seq && seq->GetNumberOfItems()) {
        // fprintf(stdout, "Found sequence in: %04x, %04x\n", tt.GetGroup(), tt.GetElement());
        anonymizeSequence(params, &dss, &tt);
      }
      ++it;
    }

    /*    gdcm::Tag tsqur(0x0008,0x1115);
    if (dss.FindDataElement(tsqur)) { // this work on the highest level (Tag is found in dss), but what if we are already in a sequence?
      //const gdcm::DataElement squr = dss.GetDataElement( tsqur );
      anonymizeSequence( params, &dss, &tsqur);
      } */

    // const gdcm::Image &image = reader.GetImage();
    // if we have the image here we can anonymize now and write again
    gdcm::Anonymizer anon;
    gdcm::File &fileToAnon = reader.GetFile();
    anon.SetFile(fileToAnon);

    gdcm::MediaStorage ms;
    ms.SetFromFile(fileToAnon);
    if (!gdcm::Defs::GetIODNameFromMediaStorage(ms)) {
      std::cerr << "The Media Storage Type of your file is not supported: " << ms << std::endl;
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
    gdcm::Trace::SetDebug(true);
    gdcm::Trace::SetWarning(true);
    gdcm::Trace::SetError(true);

    // lets add the private group entries
    // gdcm::AddTag(gdcm::Tag(0x65010010), gdcm::VR::LO, "MY NEW DATASET", reader.GetFile().GetDataSet());

    // now walk through the list of entries and apply each one to the current ds
    for (int i = 0; i < work.size(); i++) {
      // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
      std::string tag1(work[i][0]);
      std::string tag2(work[i][1]);
      std::string which(work[i][2]);
      std::string what("replace");
      bool regexp = false;
      if (work[i].size() > 3) {
        what = work[i][3];
      }
      int a = strtol(tag1.c_str(), NULL, 16);
      int b = strtol(tag2.c_str(), NULL, 16);
      // fprintf(stdout, "Tag: %s %04X %04X\n", which.c_str(), a, b);
      if (work[i].size() > 4 && work[i][4] == "regexp") {
	  regexp = true;
	  // as a test print out what we got
          std::string val = sf.ToString(gdcm::Tag(a, b));
	  std::string ns("");
	  try {
	    std::regex re(what);
	    std::smatch match;
	    if (std::regex_search(val, match, re) && match.size() > 1) {
	      for (int i = 1; i < match.size(); i++) {
		ns += match.str(i) + std::string(" ");
	      }
	    } else {
	      ns = std::string("FIONA: no match on regular expression");
	    }
	  } catch(std::regex_error& e) {
	    fprintf(stdout, "ERROR: regular expression match failed on %s,%s which: %s what: %s old: %s new: %s\n",
		    tag1.c_str(), tag2.c_str(), which.c_str(), what.c_str(), val.c_str(), ns.c_str());
	  }
	  fprintf(stdout, "show: %s,%s which: %s what: %s old: %s new: %s\n", tag1.c_str(), tag2.c_str(), which.c_str(), what.c_str(), val.c_str(), ns.c_str());
	  continue;
      }
      if (which == "BlockOwner" && what != "replace") {
        anon.Replace(gdcm::Tag(a, b), what.c_str());
        continue;
      }
      if (which == "ProjectName") {
        anon.Replace(gdcm::Tag(a, b), params->projectname.c_str());
        continue;
      }
      if (what == "replace") {
        anon.Replace(gdcm::Tag(a, b), which.c_str());
        continue;
      }
      if (what == "remove") {
        anon.Remove(gdcm::Tag(a, b));
        continue;
      }
      if (what == "empty") {
        anon.Empty(gdcm::Tag(a, b));
        continue;
      }
      if (what == "hashuid+PROJECTNAME") {
        std::string val = sf.ToString(gdcm::Tag(a, b));
        std::string hash = SHA256::digestString(val + params->projectname).toHex();
        if (which == "SOPInstanceUID") // keep a copy as the filename for the output
          filenamestring = hash.c_str();

        if (which == "SeriesInstanceUID")
          seriesdirname = hash.c_str();

        if (which == "StudyInstanceUID") {
          // we want to keep a mapping of the old and new study instance uids
          params->byThreadStudyInstanceUID.insert(std::pair<std::string, std::string>(val, hash)); // should only add this pair once
        }
        if (which == "SeriesInstanceUID") {
          // we want to keep a mapping of the old and new study instance uids
          params->byThreadSeriesInstanceUID.insert(std::pair<std::string, std::string>(val, hash)); // should only add this pair once
        }

        anon.Replace(gdcm::Tag(a, b), hash.c_str());
        // this does not replace elements inside sequences
        continue;
      }
      if (what == "hashuid" || what == "hash") {
        std::string val = sf.ToString(gdcm::Tag(a, b));
        std::string hash = SHA256::digestString(val).toHex();
        if (which == "SOPInstanceUID") // keep a copy as the filename for the output
          filenamestring = hash.c_str();

        if (which == "SeriesInstanceUID")
          seriesdirname = hash.c_str();

        if (which == "SeriesInstanceUID") {
          // we want to keep a mapping of the old and new study instance uids
          params->byThreadSeriesInstanceUID.insert(std::pair<std::string, std::string>(val, hash)); // should only add this pair once
        }

        anon.Replace(gdcm::Tag(a, b), hash.c_str());
        continue;
      }
      if (what == "keep") {
        // so we do nothing...
        continue;
      }
      if (what == "incrementdate") {
        int nd = params->dateincrement;
        std::string val = sf.ToString(gdcm::Tag(a, b));
        // parse the date string YYYYMMDD
        struct sdate date1;
        if (sscanf(val.c_str(), "%04ld%02ld%02ld", &date1.y, &date1.m, &date1.d) == 3) {
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
        continue;
      }
      if (what == "YES") {
        anon.Replace(gdcm::Tag(a, b), "YES");
        continue;
      }
      if (what == "MODIFIED") {
        anon.Replace(gdcm::Tag(a, b), "MODIFIED");
        continue;
      }
      if (what == "PROJECTNAME") {
        anon.Replace(gdcm::Tag(a, b), params->projectname.c_str());
        continue;
      }
      if (what == "SITENAME") {
        anon.Replace(gdcm::Tag(a, b), params->sitename.c_str());
        continue;
      }
      // Some entries have Re-Mapped, that could be a name on the command line or,
      // by default we should hash the id
      // fprintf(stdout, "Warning: set to what: %s %s which: %s what: %s\n", tag1.c_str(), tag2.c_str(), which.c_str(), what.c_str());
      // fallback, if everything fails we just use the which and set that's field value
      anon.Replace(gdcm::Tag(a, b), what.c_str());
    }

    // hash of the patient id
    if (params->patientid == "hashuid") {
      std::string val = sf.ToString(gdcm::Tag(0x0010, 0x0010));
      std::string hash = SHA256::digestString(val).toHex();
      anon.Replace(gdcm::Tag(0x0010, 0x0010), hash.c_str());
    } else {
      anon.Replace(gdcm::Tag(0x0010, 0x0010), params->patientid.c_str());
    }
    if (params->patientid == "hashuid") {
      std::string val = sf.ToString(gdcm::Tag(0x0010, 0x0020));
      std::string hash = SHA256::digestString(val).toHex();
      anon.Replace(gdcm::Tag(0x0010, 0x0020), hash.c_str());
    } else {
      anon.Replace(gdcm::Tag(0x0010, 0x0020), params->patientid.c_str());
    }

    // We store the computed StudyInstanceUID in the StudyID tag.
    // This is used by the default setup of Sectra to identify the study (together with the AccessionNumber field).
    std::string anonStudyInstanceUID = sf.ToString(gdcm::Tag(0x0020, 0x000D));
    anon.Replace(gdcm::Tag(0x0020, 0x0010), anonStudyInstanceUID.c_str());

    // fprintf(stdout, "project name is: %s\n", params->projectname.c_str());
    // this is a private tag --- does not work yet - we can only remove
    anon.Remove(gdcm::Tag(0x0013, 0x1010));
    /*if (!anon.Replace(gdcm::Tag(0x0013, 0x1010), params->projectname.c_str())) {
      gdcm::Trace::SetDebug( true );
      gdcm::Trace::SetWarning( true );
      bool ok = anon.Empty(gdcm::Tag(0x0013, 0x1010)); // empty the field
                                                       //      if (!ok)
                                                       //        fprintf(stderr, "failed setting tags 0013,1010 to empty.\n");
    }*/
    anon.Remove(gdcm::Tag(0x0013, 0x1013));
    /*if (!anon.Replace(gdcm::Tag(0x0013, 0x1013), params->sitename.c_str())) {
      bool ok = anon.Empty(gdcm::Tag(0x0013, 0x1013));
//      if (!ok)
//        fprintf(stderr, "failed setting tags 0013,1013 to empty.\n");
    }*/
    anon.Remove(gdcm::Tag(0x0013, 0x1011));
    anon.Remove(gdcm::Tag(0x0013, 0x1012));
    /*if (!anon.Replace(gdcm::Tag(0x0013, 0x1012), params->sitename.c_str())) {
      //fprintf(stderr, "Cannot set private tag 0013, 1012, try to set to 0\n");
      bool ok = anon.Empty(gdcm::Tag(0x0013, 0x1012)); // could fail if the element does not exist
//      if (!ok)
//        fprintf(stderr, "failed setting tags 0013,1012 to empty.\n");
    } */

    // ok save the file again
    std::string imageInstanceUID = filenamestring;
    if (imageInstanceUID == "") {
      fprintf(stderr, "Warning: cannot read image instance uid from %s, create a new one.\n", filename);
      gdcm::UIDGenerator gen;
      imageInstanceUID = gen.Generate();
      filenamestring = imageInstanceUID;
    }
    std::string fn = params->outputdir + "/" + filenamestring + ".dcm";
    if (params->byseries) {
      // use the series instance uid as a directory name
      std::string dn = params->outputdir + "/" + seriesdirname;
      struct stat buffer;
      if (!(stat(dn.c_str(), &buffer) == 0)) {
        // DIR *dir = opendir(dn.c_str());
        // if ( ENOENT == errno)	{
        mkdir(dn.c_str(), 0777);
      } // else {
        // closedir(dir);
      //}
      fn = params->outputdir + "/" + seriesdirname + "/" + filenamestring + ".dcm";
    }

    fprintf(stdout, "[%d] write to file: %s\n", params->thread, fn.c_str());
    std::string outfilename(fn);

    // save the file again to the output
    gdcm::Writer writer;
    writer.SetFile(fileToAnon);
    writer.SetFileName(outfilename.c_str());
    try {
      if (!writer.Write()) {
        fprintf(stderr, "Error [#file: %d, thread: %d] writing file \"%s\" to \"%s\".\n", file, params->thread, filename, outfilename.c_str());
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

void ReadFiles(size_t nfiles, const char *filenames[], const char *outputdir, const char *patientid, int dateincrement, bool byseries, int numthreads,
               const char *projectname, const char *sitename, const char *siteid, std::string storeMappingAsJSON) {
  // \precondition: nfiles > 0
  assert(nfiles > 0);

  // lets change the DICOM dictionary and add some private tags - this is still not sufficient to be able to write the private tags
  gdcm::Global gl;
  if (gl.GetDicts().GetPrivateDict().FindDictEntry(gdcm::Tag(0x0013, 0x0010))) {
    gl.GetDicts().GetPrivateDict().RemoveDictEntry(gdcm::Tag(0x0013, 0x0010));
  }
  gl.GetDicts().GetPrivateDict().AddDictEntry(gdcm::Tag(0x0013, 0x0010),
                                              gdcm::DictEntry("Private Creator Group CTP-LIKE", "0x0013, 0x0010", gdcm::VR::LO, gdcm::VM::VM1));

  if (gl.GetDicts().GetPrivateDict().FindDictEntry(gdcm::Tag(0x0013, 0x1010))) {
    gl.GetDicts().GetPrivateDict().RemoveDictEntry(gdcm::Tag(0x0013, 0x1010));
  }
  gl.GetDicts().GetPrivateDict().AddDictEntry(gdcm::Tag(0x0013, 0x1010), gdcm::DictEntry("ProjectName", "0x0013, 0x1010", gdcm::VR::LO, gdcm::VM::VM1));

  if (gl.GetDicts().GetPrivateDict().FindDictEntry(gdcm::Tag(0x0013, 0x1013))) {
    gl.GetDicts().GetPrivateDict().RemoveDictEntry(gdcm::Tag(0x0013, 0x1013));
  }
  gl.GetDicts().GetPrivateDict().AddDictEntry(gdcm::Tag(0x0013, 0x1013), gdcm::DictEntry("SiteID", "0x0013, 0x1013", gdcm::VR::LO, gdcm::VM::VM1));

  if (gl.GetDicts().GetPrivateDict().FindDictEntry(gdcm::Tag(0x0013, 0x1012))) {
    gl.GetDicts().GetPrivateDict().RemoveDictEntry(gdcm::Tag(0x0013, 0x1012));
  }
  gl.GetDicts().GetPrivateDict().AddDictEntry(gdcm::Tag(0x0013, 0x1012), gdcm::DictEntry("SiteName", "0x0013, 0x1012", gdcm::VR::LO, gdcm::VM::VM1));

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
  if (nfiles <= numthreads) {
    numthreads = 1; // fallback if we don't have enough files to process
  }

  const unsigned int nthreads = numthreads; // how many do we want to use?
  threadparams params[nthreads];

  pthread_t *pthread = new pthread_t[nthreads];

  // There is nfiles, and nThreads
  assert(nfiles >= nthreads);
  const size_t partition = nfiles / nthreads;
  for (unsigned int thread = 0; thread < nthreads; ++thread) {
    params[thread].filenames = filenames + thread * partition;
    params[thread].outputdir = outputdir;
    params[thread].patientid = patientid;
    params[thread].nfiles = partition;
    params[thread].dateincrement = dateincrement;
    params[thread].byseries = byseries;
    params[thread].thread = thread;
    params[thread].projectname = projectname;
    params[thread].sitename = sitename;
    params[thread].siteid = siteid;
    if (thread == nthreads - 1) {
      // There is slightly more files to process in this thread:
      params[thread].nfiles += nfiles % nthreads;
    }
    assert(thread * partition < nfiles);
    int res = pthread_create(&pthread[thread], NULL, ReadFilesThread, &params[thread]);
    if (res) {
      std::cerr << "Unable to start a new thread, pthread returned: " << res << std::endl;
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

  // we can access the per thread storage of study instance uid mappings now
  if (storeMappingAsJSON.length() > 0) {
    std::map<std::string, std::string> uidmappings1;
    std::map<std::string, std::string> uidmappings2;
    for (unsigned int thread = 0; thread < nthreads; thread++) {
      for (std::map<std::string,std::string>::iterator it = params[thread].byThreadStudyInstanceUID.begin(); it != params[thread].byThreadStudyInstanceUID.end(); ++it) {
	uidmappings1.insert( std::pair<std::string, std::string> (it->first,it->second) );
      }
    }
    for (unsigned int thread = 0; thread < nthreads; thread++) {
      for (std::map<std::string,std::string>::iterator it = params[thread].byThreadSeriesInstanceUID.begin(); it != params[thread].byThreadSeriesInstanceUID.end(); ++it) {
	uidmappings2.insert( std::pair<std::string, std::string> (it->first,it->second) );
      }
    }
    nlohmann::json ar;
    ar["StudyInstanceUID"] = {};
    ar["SeriesInstanceUID"] = {};
    for (std::map<std::string,std::string>::iterator it = uidmappings1.begin(); it != uidmappings1.end(); ++it) {
      ar["StudyInstanceUID"][it->first] = it->second;
    }
    for (std::map<std::string,std::string>::iterator it = uidmappings2.begin(); it != uidmappings2.end(); ++it) {
      ar["SeriesInstanceUID"][it->first] = it->second;
    }

    std::ofstream jsonfile(storeMappingAsJSON);
    jsonfile << ar;
    jsonfile.flush();
    jsonfile.close();
  }

  delete[] pthread;
}

struct Arg : public option::Arg {
  static option::ArgStatus Required(const option::Option &option, bool) { return option.arg == 0 ? option::ARG_ILLEGAL : option::ARG_OK; }
  static option::ArgStatus Empty(const option::Option &option, bool) { return (option.arg == 0 || option.arg[0] == 0) ? option::ARG_OK : option::ARG_IGNORE; }
};

enum optionIndex {
  UNKNOWN,
  HELP,
  INPUT,
  OUTPUT,
  PATIENTID,
  PROJECTNAME,
  SITENAME,
  DATEINCREMENT,
  EXPORTANON,
  BYSERIES,
  NUMTHREADS,
  TAGCHANGE,
  STOREMAPPING,
  SITEID,
  REGTAGCHANGE
};
const option::Descriptor usage[] = {
    {UNKNOWN, 0, "", "", option::Arg::None,
     "USAGE: anonymize [options]\n\n"
     "Options:"},
    {HELP, 0, "", "help", Arg::None,
     "  --help  \tAnonymize DICOM images. Read DICOM image series and write "
     "out an anonymized version of the files based on the recommendations of "
     "the cancer imaging archive."},
    {INPUT, 0, "i", "input", Arg::Required, "  --input, -i  \tInput directory."},
    {OUTPUT, 0, "o", "output", Arg::Required, "  --output, -o  \tOutput directory."},
    {PATIENTID, 0, "p", "patientid", Arg::Required, "  --patientid, -p  \tPatient ID after anonymization (default is \"hashuid\" to hash the existing id)."},
    {PROJECTNAME, 0, "j", "projectname", Arg::Required, "  --projectname, -j  \tProject name."},
    {SITENAME, 0, "s", "sitename", Arg::Required, "  --sitename, -s  \tSite name."},
    {SITEID, 0, "d", "siteid", Arg::Required, "  --siteid, -s  \tSite id."},
    {DATEINCREMENT, 0, "d", "dateincrement", Arg::Required, "  --dateincrement, -d  \tNumber of days that should be added to dates."},
    {EXPORTANON, 0, "a", "exportanon", Arg::Required,
     "  --exportanon, -a  \tWrites the anonymization structure as a json file "
     "to disk and quits the program. There is no way to import a new file currently."},
    {BYSERIES, 0, "b", "byseries", Arg::None,
     "  --byseries, -b  \tWrites each DICOM file into a separate directory "
     "by image series."},
    {STOREMAPPING, 0, "m", "storemapping", Arg::None, "  --storemapping, -m  \tStore the StudyInstanceUID mapping as a JSON file."},
    {TAGCHANGE, 0, "P", "tagchange", Arg::Required, "  --tagchange, -P  \tChanges the default behavior for a tag in the build-in rules."},
    {REGTAGCHANGE, 0, "R", "regtagchange", Arg::Required, "  --regtagchange, -R  \tChanges the default behavior for a tag in the build-in rules (understands regular expressions, retains all capturing groups)."},
    {NUMTHREADS, 0, "t", "numthreads", Arg::Required, "  --numthreads, -t  \tHow many threads should be used (default 4)."},
    {UNKNOWN, 0, "", "", Arg::None,
     "\nExamples:\n"
     "  anonymize --input directory --output directory --patientid bla -d 42 -b\n"
     "  anonymize --exportanon rules.json\n"
     "  anonymize --tagchange \"0008,0080=PROJECTNAME\" --tagchange \"0008,0081=bla\" \\"
     "            --exportanon rules.json\n"
     "  anonymize --help\n"},
    {0, 0, 0, 0, 0, 0}};

// get all files in all sub-directories, does some recursive calls so it might take a while
// TODO: would be good to start anonymizing already while its still trying to find more files...
std::vector<std::string> listFiles(const std::string &path, std::vector<std::string> files) {
  if (auto dir = opendir(path.c_str())) {
    while (auto f = readdir(dir)) {
      // check for '.' and '..', but allow other names that start with a dot
      if (((strlen(f->d_name) == 1) && (f->d_name[0] == '.')) || ((strlen(f->d_name) == 2) && (f->d_name[0] == '.') && (f->d_name[1] == '.')))
        continue;
      if (f->d_type == DT_DIR) {
        std::vector<std::string> ff = listFiles(path + "/" + f->d_name + "/", files);
        // append the returned files to files
        for (int i = 0; i < ff.size(); i++) {
          // problem is that we add files here several times if we don't check first.. don't understand why
          if (std::find(files.begin(), files.end(), ff[i]) == files.end())
            files.push_back(ff[i]);
        }
      }

      if (f->d_type == DT_REG) {
        // cb(path + f->d_name);
        if (std::find(files.begin(), files.end(), path + "/" + f->d_name) == files.end())
          files.push_back(path + "/" + f->d_name);
      }
    }
    closedir(dir);
  }
  return files;
}

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
    std::cout << "Unknown option: " << std::string(opt->name, opt->namelen) << "\n";

  std::string input;
  std::string output;
  std::string patientID = "hashuid"; // mark the default value as hash the existing uids for patientID and patientName
  std::string sitename = "";
  std::string siteid = "";
  int dateincrement = 42;
  std::string exportanonfilename = ""; // anon.json
  bool byseries = false;
  int numthreads = 4;
  std::string projectname = "";
  std::string storeMappingAsJSON = "";
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
      case SITENAME:
        if (opt.arg) {
          fprintf(stdout, "--sitename '%s'\n", opt.arg);
          sitename = opt.arg;
        } else {
          fprintf(stdout, "--sitename needs a string specified\n");
          exit(-1);
        }
        break;
      case SITEID:
        if (opt.arg) {
          fprintf(stdout, "--siteid '%s'\n", opt.arg);
          siteid = opt.arg;
        } else {
          fprintf(stdout, "--siteid needs a string specified\n");
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
      case STOREMAPPING:
        fprintf(stdout, "--storemapping\n");
        storeMappingAsJSON = "mapping.json";
        break;
      case TAGCHANGE:
        if (opt.arg) {
          fprintf(stdout, "--tagchange %s\n", opt.arg);
          std::string tagchange = opt.arg;
          // apply this tag to the rules, should overwrite what was in there, or add another rule
          std::string tag1;
          std::string tag2;
          std::string res;
          int posEqn = tagchange.find("=");
          if (posEqn == std::string::npos) {
            fprintf(stdout, "--tagchange error, string does not match pattern %%o,%%o=%%s\n");
            exit(-1);
          }
          res = tagchange.substr(posEqn + 1, std::string::npos); // until the end of the string
          std::string front = tagchange.substr(0, posEqn);
          int posComma = front.find(",");
          if (posComma == std::string::npos) {
            fprintf(stdout, "--tagchange error, string does not match pattern %%o,%%o=%%s\n");
            exit(-1);
          }
          tag1 = front.substr(0, posComma);
          tag2 = front.substr(posComma + 1, std::string::npos);
          fprintf(stdout, "got a tagchange of %s,%s = %s\n", tag1.c_str(), tag2.c_str(), res.c_str());
          int a = strtol(tag1.c_str(), NULL, 16);
          int b = strtol(tag2.c_str(), NULL, 16); // did this work? we should check here and not just add
          // now check in work if we add or replace this rule
          bool found = false;
          for (int i = 0; i < work.size(); i++) {
            // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
            std::string ttag1(work[i][0]);
            std::string ttag2(work[i][1]);
            std::string twhich(work[i][2]);
            if (tag1 == ttag1 && tag2 == ttag2) {
              // found and overwrite
              found = true;
              work[i][3] = res; // overwrite the value, [2] is name
            }
          }
          if (!found) {
            // append as a new rule
            nlohmann::json ar;
            ar.push_back(tag1);
            ar.push_back(tag2);
            ar.push_back(res);
            ar.push_back(res);
            work.push_back(ar);
          }
        } else {
          fprintf(stdout, "--tagchange needs a string specification like this \"0080,0010=ANON\"\n");
          exit(-1);
        }
        break;
      case REGTAGCHANGE:
        if (opt.arg) {
          fprintf(stdout, "--regtagchange %s\n", opt.arg);
          std::string tagchange = opt.arg;
          // apply this tag to the rules, should overwrite what was in there, or add another rule
          std::string tag1;
          std::string tag2;
          std::string res;
          int posEqn = tagchange.find("=");
          if (posEqn == std::string::npos) {
            fprintf(stdout, "--regtagchange error, string does not match pattern %%o,%%o=%%s\n");
            exit(-1);
          }
          res = tagchange.substr(posEqn + 1, std::string::npos); // until the end of the string
          std::string front = tagchange.substr(0, posEqn);
          int posComma = front.find(",");
          if (posComma == std::string::npos) {
            fprintf(stdout, "--regtagchange error, string does not match pattern %%o,%%o=%%s\n");
            exit(-1);
          }
          tag1 = front.substr(0, posComma);
          tag2 = front.substr(posComma + 1, std::string::npos);
          fprintf(stdout, "got a regtagchange of %s,%s = %s\n", tag1.c_str(), tag2.c_str(), res.c_str());
          int a = strtol(tag1.c_str(), NULL, 16);
          int b = strtol(tag2.c_str(), NULL, 16); // did this work? we should check here and not just add
          // now check in work if we add or replace this rule
          bool found = false;
          for (int i = 0; i < work.size(); i++) {
            // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
            std::string ttag1(work[i][0]);
            std::string ttag2(work[i][1]);
            std::string twhich(work[i][2]);
            if (tag1 == ttag1 && tag2 == ttag2) {
              // found and overwrite
              found = true;
              work[i][3] = res; // overwrite the value, [2] is name
	      work[i][4] = "regexp"; // mark this as a regular expression tag change
            }
          }
          if (!found) {
            // append as a new rule
            nlohmann::json ar;
            ar.push_back(tag1);
            ar.push_back(tag2);
            ar.push_back(res);
            ar.push_back(res);
	    ar.push_back(std::string("regexp"));
            work.push_back(ar);
          }
        } else {
          fprintf(stdout, "--regtagchange needs a string specification like this \"0080,0010=\\[(.*) [0-9]+\\]\"\n");
          exit(-1);
        }
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
    std::vector<std::string> files;
    files = listFiles(input.c_str(), files);

    const size_t nfiles = files.size();
    const char **filenames = new const char *[nfiles];
    for (unsigned int i = 0; i < nfiles; ++i) {
      filenames[i] = files[i].c_str();
    }
    if (storeMappingAsJSON.length() > 0) {
      storeMappingAsJSON = output + std::string("/") + storeMappingAsJSON;
    }
    // ReadFiles(nfiles, filenames, output.c_str(), numthreads, confidence, storeMappingAsJSON);
    ReadFiles(nfiles, filenames, output.c_str(), patientID.c_str(), dateincrement, byseries, numthreads, projectname.c_str(), sitename.c_str(), siteid.c_str(),
              storeMappingAsJSON);
    delete[] filenames;
  } else {
    // its a single file, process that
    const char **filenames = new const char *[1];
    filenames[0] = input.c_str();
    // ReadFiles(1, filenames, output.c_str(), 1, confidence, storeMappingAsJSON);
    ReadFiles(1, filenames, output.c_str(), patientID.c_str(), dateincrement, byseries, numthreads, projectname.c_str(), sitename.c_str(), siteid.c_str(),
              storeMappingAsJSON);
  }

  return 0;
}

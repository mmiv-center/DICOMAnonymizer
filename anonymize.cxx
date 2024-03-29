/*=========================================================================

  Program: Anonymization using gdcm

  Copyright (c) 2024 Hauke Bartsch

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
#include "gdcmPrivateTag.h"
#include "gdcmDataSetHelper.h"
#include "json.hpp"
#include "optionparser.h"
#include <gdcmUIDGenerator.h>

#include <dirent.h>
#include <errno.h>
#include <exception>
#include <stdexcept>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#include <chrono>
#include <map>
#include <unordered_set>
#include <pthread.h>
#include <regex>
#include <stdio.h>
#include <thread>

#include <filesystem> // needs C++-17 (we are now on c++20)
namespace fs = std::filesystem;

#cmakedefine VERSION_DATE "@VERSION_DATE@"

struct threadparams {
  const char **filenames;
  size_t nfiles;
  char *scalarpointer;
  std::string outputdir;
  std::string patientid;
  std::string projectname;
  std::string sitename;
  std::string eventname;
  std::string siteid;
  int dateincrement;
  bool byseries;
  int thread; // number of the thread
  bool old_style_uid;
  // each thread will store here the study instance uid (original and mapped)
  std::map<std::string, std::string> byThreadStudyInstanceUID;
  std::map<std::string, std::string> byThreadSeriesInstanceUID;
};

int debug_level = 0;

// Coding Scheme Designator        Code Value      Code Meaning    Body Part Examined
nlohmann::json allowedBodyParts = nlohmann::json::array({{"XXX", "XXXXXXXX", "BODYPART", "BODYPART"}, // this top element is only a fallback, not in the standard!
                                                         {"SCT", "818981001", "Abdomen", "ABDOMEN"},
                                                         {"SCT", "818982008", "Abdomen and Pelvis", "ABDOMENPELVIS"},
                                                         {"SCT", "7832008", "Abdominal aorta", "ABDOMINALAORTA"},
                                                         {"SCT", "85856004", "Acromioclavicular joint", "ACJOINT"},
                                                         {"SCT", "23451007", "Adrenal gland", "ADRENAL"},
                                                         {"SCT", "77012006", "Amniotic fluid", "AMNIOTICFLUID"},
                                                         {"SCT", "70258002", "Ankle joint", "ANKLE"},
                                                         {"SCT", "128585006", "Anomalous pulmonary vein", ""},
                                                         {"SCT", "128553008", "Antecubital vein", "ANTECUBITALV"},
                                                         {"SCT", "194996006", "Anterior cardiac vein", "ANTCARDIACV"},
                                                         {"SCT", "60176003", "Anterior cerebral artery", "ACA"},
                                                         {"SCT", "8012006", "Anterior communicating artery", "ANTCOMMA"},
                                                         {"SCT", "17388009", "Anterior spinal artery", "ANTSPINALA"},
                                                         {"SCT", "68053000", "Anterior tibial artery", "ANTTIBIALA"},
                                                         {"SCT", "53505006", "Anus", ""},
                                                         {"SCT", "110612005", "Anus, rectum and sigmoid colon", "ANUSRECTUMSIGMD"},
                                                         {"SCT", "15825003", "Aorta", "AORTA"},
                                                         {"SCT", "57034009", "Aortic arch", "AORTICARCH"},
                                                         {"SCT", "128551005", "Aortic fistula", ""},
                                                         {"SCT", "128564006", "Apex of left ventricle", ""},
                                                         {"SCT", "86598002", "Apex of Lung", ""},
                                                         {"SCT", "128565007", "Apex of right ventricle", ""},
                                                         {"SCT", "66754008", "Appendix", "APPENDIX"},
                                                         {"SCT", "51114001", "Artery", "ARTERY"},
                                                         {"SCT", "54247002", "Ascending aorta", "ASCAORTA"},
                                                         {"SCT", "9040008", "Ascending colon", "ASCENDINGCOLON"},
                                                         {"SCT", "59652004", "Atrium", ""},
                                                         {"SCT", "91470000", "Axilla", "AXILLA"},
                                                         {"SCT", "67937003", "Axillary Artery", "AXILLARYA"},
                                                         {"SCT", "68705008", "Axillary vein", "AXILLARYV"},
                                                         {"SCT", "72107004", "Azygos vein", "AZYGOSVEIN"},
                                                         {"SCT", "77568009", "Back", "BACK"},
                                                         {"SCT", "128981007", "Baffle", ""},
                                                         {"SCT", "59011009", "Basilar artery", "BASILARA"},
                                                         {"SCT", "28273000", "Bile duct", "BILEDUCT"},
                                                         {"SCT", "34707002", "Biliary tract", "BILIARYTRACT"},
                                                         {"SCT", "89837001", "Bladder", "BLADDER"},
                                                         {"SCT", "110837003", "Bladder and urethra", "BLADDERURETHRA"},
                                                         {"SCT", "91830000", "Body conduit", ""},
                                                         {"SCT", "72001000", "Bone of lower limb", ""},
                                                         {"SCT", "371195002", "Bone of upper limb", ""},
                                                         {"SCT", "128548003", "Boyd's perforating vein", ""},
                                                         {"SCT", "17137000", "Brachial artery", "BRACHIALA"},
                                                         {"SCT", "20115005", "Brachial vein", "BRACHIALV"},
                                                         {"SCT", "12738006", "Brain", "BRAIN"},
                                                         {"SCT", "76752008", "Breast", "BREAST"},
                                                         {"SCT", "34411009", "Broad ligament", ""},
                                                         {"SCT", "955009", "Bronchus", "BRONCHUS"},
                                                         {"SCT", "60819002", "Buccal region of face", ""},
                                                         {"SCT", "46862004", "Buttock", "BUTTOCK"},
                                                         {"SCT", "80144004", "Calcaneus", "CALCANEUS"},
                                                         {"SCT", "53840002", "Calf of leg", "CALF"},
                                                         {"SCT", "2334006", "Calyx", ""},
                                                         {"SCT", "69105007", "Carotid Artery", "CAROTID"},
                                                         {"SCT", "21479005", "Carotid bulb", "BULB"},
                                                         {"SCT", "57850000", "Celiac artery", "CELIACA"},
                                                         {"SCT", "20699002", "Cephalic vein", "CEPHALICV"},
                                                         {"SCT", "113305005", "Cerebellum", "CEREBELLUM"},
                                                         {"SCT", "88556005", "Cerebral artery", "CEREBRALA"},
                                                         {"SCT", "372073000", "Cerebral hemisphere", "CEREBHEMISPHERE"},
                                                         {"SCT", "122494005", "Cervical spine", "CSPINE"},
                                                         {"SCT", "1217257000", "Cervico-thoracic spine", "CTSPINE"},
                                                         {"SCT", "71252005", "Cervix", "CERVIX"},
                                                         {"SCT", "60819002", "Cheek", "CHEEK"},
                                                         {"SCT", "43799004", "Chest", "CHEST"},
                                                         {"SCT", "416775004", "Chest, Abdomen and Pelvis", "CHESTABDPELVIS"},
                                                         {"SCT", "416550000", "Chest and Abdomen", "CHESTABDOMEN"},
                                                         {"SCT", "80621003", "Choroid plexus", "CHOROIDPLEXUS"},
                                                         {"SCT", "11279006", "Circle of Willis", "CIRCLEOFWILLIS"},
                                                         {"SCT", "51299004", "Clavicle", "CLAVICLE"},
                                                         {"SCT", "64688005", "Coccyx", "COCCYX"},
                                                         {"SCT", "71854001", "Colon", "COLON"},
                                                         {"SCT", "253276007", "Common atrium", ""},
                                                         {"SCT", "79741001", "Common bile duct", "COMMONBILEDUCT"},
                                                         {"SCT", "32062004", "Common carotid artery", "CCA"},
                                                         {"SCT", "181347005", "Common femoral artery", "CFA"},
                                                         {"SCT", "397363009", "Common femoral vein", "CFV"},
                                                         {"SCT", "73634005", "Common iliac artery", "COMILIACA"},
                                                         {"SCT", "46027005", "Common iliac vein", "COMILIACV"},
                                                         {"SCT", "45503006", "Common ventricle", ""},
                                                         {"SCT", "128555001", "Congenital coronary artery fistula to left atrium", ""},
                                                         {"SCT", "128556000", "Congenital coronary artery fistula to left ventricle", ""},
                                                         {"SCT", "128557009", "Congenital coronary artery fistula to right atrium", ""},
                                                         {"SCT", "128558004", "Congenital coronary artery fistula to right ventricle", ""},
                                                         {"SCT", "111289009", "Pulmonary arteriovenous fistula", ""},
                                                         {"SCT", "28726007", "Cornea", "CORNEA"},
                                                         {"SCT", "41801008", "Coronary artery", "CORONARYARTERY"},
                                                         {"SCT", "90219004", "Coronary sinus", "CORONARYSINUS"},
                                                         {"SCT", "128320002", "Cranial venous system", ""},
                                                         {"SCT", "32672002", "Descending aorta", "DESCAORTA"},
                                                         {"SCT", "32622004", "Descending colon", "DESCENDINGCOLON"},
                                                         {"SCT", "128554002", "Dodd's perforating vein", ""},
                                                         {"SCT", "38848004", "Duodenum", "DUODENUM"},
                                                         {"SCT", "117590005", "Ear", "EAR"},
                                                         {"SCT", "16953009", "Elbow joint", "ELBOW"},
                                                         {"SCT", "51114001", "Endo-arterial", "ENDOARTERIAL"},
                                                         {"SCT", "80891009", "Endo-cardiac", "ENDOCARDIAC"},
                                                         {"SCT", "32849002", "Endo-esophageal", "ENDOESOPHAGEAL"},
                                                         {"SCT", "2739003", "Endometrium", "ENDOMETRIUM"},
                                                         {"SCT", "53342003", "Endo-nasal", "ENDONASAL"},
                                                         {"SCT", "18962004", "Endo-nasopharyngeal", "ENDONASOPHARYNYX"},
                                                         {"SCT", "34402009", "Endo-rectal", "ENDORECTAL"},
                                                         {"SCT", "64033007", "Endo-renal", "ENDORENAL"},
                                                         {"SCT", "87953007", "Endo-ureteric", "ENDOURETERIC"},
                                                         {"SCT", "13648007", "Endo-urethral", "ENDOURETHRAL"},
                                                         {"SCT", "76784001", "Endo-vaginal", "ENDOVAGINAL"},
                                                         {"SCT", "59820001", "Endo-vascular", "ENDOVASCULAR"},
                                                         {"SCT", "29092000", "Endo-venous", "ENDOVENOUS"},
                                                         {"SCT", "48367006", "Endo-vesical", "ENDOVESICAL"},
                                                         {"SCT", "38266002", "Entire body", "WHOLEBODY"},
                                                         {"SCT", "87644002", "Epididymis", "EPIDIDYMIS"},
                                                         {"SCT", "27947004", "Epigastric region", "EPIGASTRIC"},
                                                         {"SCT", "32849002", "Esophagus", "ESOPHAGUS"},
                                                         {"SCT", "110861005", "Esophagus, stomach and duodenum", ""},
                                                         {"SCT", "84301002", "External auditory canal", "EAC"},
                                                         {"SCT", "22286001", "External carotid artery", "ECA"},
                                                         {"SCT", "113269004", "External iliac artery", "EXTILIACA"},
                                                         {"SCT", "63507001", "External iliac vein", "EXTILIACV"},
                                                         {"SCT", "71585003", "External jugular vein", "EXTJUGV"},
                                                         {"SCT", "66019005", "Extremity", "EXTREMITY"},
                                                         {"SCT", "81745001", "Eye", "EYE"},
                                                         {"SCT", "80243003", "Eyelid", "EYELID"},
                                                         {"SCT", "371398005", "Eye region", ""},
                                                         {"SCT", "89545001", "Face", "FACE"},
                                                         {"SCT", "23074001", "Facial artery", "FACIALA"},
                                                         {"SCT", "91397008", "Facial bones", ""},
                                                         {"SCT", "7657000", "Femoral artery", "FEMORALA"},
                                                         {"SCT", "83419000", "Femoral vein", "FEMORALV"},
                                                         {"SCT", "71341001", "Femur", "FEMUR"},
                                                         {"", "", "Fetal arm", "FETALARM"},
                                                         {"", "", "Fetal digit", "FETALDIGIT"},
                                                         {"", "", "Fetal heart", "FETALHEART"},
                                                         {"", "", "Fetal leg", "FETALLEG"},
                                                         {"", "", "Fetal pole", "FETALPOLE"},
                                                         {"SCT", "87342007", "Fibula", "FIBULA"},
                                                         {"SCT", "7569003", "Finger", "FINGER"},
                                                         {"SCT", "58602004", "Flank", "FLANK"},
                                                         {"SCT", "79361005", "Fontanel of skull", "FONTANEL"},
                                                         {"SCT", "56459004", "Foot", "FOOT"},
                                                         {"SCT", "14975008", "Forearm", "FOREARM"},
                                                         {"SCT", "35918002", "Fourth ventricle", "4THVENTRICLE"},
                                                         {"SCT", "28231008", "Gallbladder", "GALLBLADDER"},
                                                         {"SCT", "110568007", "Gastric vein", "GASTRICV"},
                                                         {"SCT", "128559007", "Genicular artery", "GENICULARA"},
                                                         {"SCT", "300571009", "Gestational sac", "GESTSAC"},
                                                         {"SCT", "46862004", "Gluteal region", "GLUTEAL"},
                                                         {"SCT", "5928000", "Great cardiac vein", ""},
                                                         {"SCT", "60734001", "Great saphenous vein", "GSV"},
                                                         {"SCT", "85562004", "Hand", "HAND"},
                                                         {"SCT", "69536005", "Head", "HEAD"},
                                                         {"SCT", "774007", "Head and Neck", "HEADNECK"},
                                                         {"SCT", "80891009", "Heart", "HEART"},
                                                         {"SCT", "76015000", "Hepatic artery", "HEPATICA"},
                                                         {"SCT", "8993003", "Hepatic vein", "HEPATICV"},
                                                         {"SCT", "24136001", "Hip joint", "HIP"},
                                                         {"SCT", "85050009", "Humerus", "HUMERUS"},
                                                         {"SCT", "128560002", "Hunterian perforating vein", ""},
                                                         {"SCT", "11708003", "Hypogastric region", "HYPOGASTRIC"},
                                                         {"SCT", "81502006", "Hypopharynx", "HYPOPHARYNX"},
                                                         {"SCT", "34516001", "Ileum", "ILEUM"},
                                                         {"SCT", "299716001", "Iliac and/or femoral artery", ""},
                                                         {"SCT", "10293006", "Iliac artery", "ILIACA"},
                                                         {"SCT", "244411005", "Iliac vein", "ILIACV"},
                                                         {"SCT", "22356005", "Ilium", "ILIUM"},
                                                         {"SCT", "195416006", "Inferior cardiac vein", ""},
                                                         {"SCT", "51249003", "Inferior left pulmonary vein", ""},
                                                         {"SCT", "33795007", "Inferior mesenteric artery", "INFMESA"},
                                                         {"SCT", "113273001", "Inferior right pulmonary vein", ""},
                                                         {"SCT", "64131007", "Inferior vena cava", "INFVENACAVA"},
                                                         {"SCT", "26893007", "Inguinal region", "INGUINAL"},
                                                         {"SCT", "12691009", "Innominate artery", "INNOMINATEA"},
                                                         {"SCT", "8887007", "Innominate vein", "INNOMINATEV"},
                                                         {"SCT", "361078006", "Internal Auditory Canal", "IAC"},
                                                         {"SCT", "86117002", "Internal carotid artery", "ICA"},
                                                         {"SCT", "90024005", "Internal iliac artery", "INTILIACA"},
                                                         {"SCT", "12123001", "Internal jugular vein", "INTJUGULARV"},
                                                         {"SCT", "69327007", "Internal mammary artery", "INTMAMMARYA"},
                                                         {"SCT", "818987002", "Intra-abdominopelvic", ""},
                                                         {"SCT", "131183008", "Intra-articular", ""},
                                                         {"SCT", "1101003", "Intracranial", "INTRACRANIAL"},
                                                         {"SCT", "32849002", "Intra-esophageal", ""},
                                                         {"SCT", "816989007", "Intra-pelvic", ""},
                                                         {"SCT", "43799004", "Intra-thoracic", ""},
                                                         {"SCT", "661005", "Jaw region", "JAW"},
                                                         {"SCT", "21306003", "Jejunum", "JEJUNUM"},
                                                         {"SCT", "39352004", "Joint", "JOINT"},
                                                         {"SCT", "128563000", "Juxtaposed atrial appendage", ""},
                                                         {"SCT", "64033007", "Kidney", "KIDNEY"},
                                                         {"SCT", "72696002", "Knee", "KNEE"},
                                                         {"SCT", "59749000", "Lacrimal artery", "LACRIMALA"},
                                                         {"SCT", "128979005", "Lacrimal artery of right eye", ""},
                                                         {"SCT", "14742008", "Large intestine", "LARGEINTESTINE"},
                                                         {"SCT", "4596009", "Larynx", "LARYNX"},
                                                         {"SCT", "66720007", "Lateral Ventricle", "LATVENTRICLE"},
                                                         {"SCT", "82471001", "Left atrium", "LATRIUM"},
                                                         {"SCT", "33626005", "Left auricular appendage", ""},
                                                         {"SCT", "113270003", "Left femoral artery", "LFEMORALA"},
                                                         {"SCT", "273202007", "Left hepatic vein", "LHEPATICV"},
                                                         {"SCT", "133945003", "Left hypochondriac region", "LHYPOCHONDRIAC"},
                                                         {"SCT", "85119005", "Left inguinal region", "LINGUINAL"},
                                                         {"SCT", "68505006", "Left lower quadrant of abdomen", "LLQ"},
                                                         {"SCT", "1017210004", "Left lumbar region", "LLUMBAR"},
                                                         {"SCT", "70253006", "Left portal vein", "LPORTALV"},
                                                         {"SCT", "50408007", "Left pulmonary artery", "LPULMONARYA"},
                                                         {"SCT", "86367003", "Left upper quadrant of abdomen", "LUQ"},
                                                         {"SCT", "87878005", "Left ventricle", "LVENTRICLE"},
                                                         {"SCT", "70238003", "Left ventricle inflow", ""},
                                                         {"SCT", "13418002", "Left ventricle outflow tract", ""},
                                                         {"SCT", "113264009", "Lingual artery", "LINGUALA"},
                                                         {"SCT", "10200004", "Liver", "LIVER"},
                                                         {"SCT", "19100000", "Lower inner quadrant of breast", ""},
                                                         {"SCT", "30021000", "Lower leg", "LOWERLEG"},
                                                         {"SCT", "61685007", "Lower limb", "LOWERLIMB"},
                                                         {"SCT", "33564002", "Lower outer quadrant of breast", ""},
                                                         {"SCT", "34635009", "Lumbar artery", "LUMBARA"},
                                                         {"SCT", "52612000", "Lumbar region", "LUMBAR"},
                                                         {"SCT", "122496007", "Lumbar spine", "LSPINE"},
                                                         {"SCT", "1217253001", "Lumbo-sacral spine", "LSSPINE"},
                                                         {"SCT", "91747007", "Lumen of blood vessel", "LUMEN"},
                                                         {"SCT", "39607008", "Lung", "LUNG"},
                                                         {"SCT", "91609006", "Mandible", "MANDIBLE"},
                                                         {"SCT", "59066005", "Mastoid bone", "MASTOID"},
                                                         {"SCT", "70925003", "Maxilla", "MAXILLA"},
                                                         {"SCT", "72410000", "Mediastinum", "MEDIASTINUM"},
                                                         {"SCT", "86570000", "Mesenteric artery", "MESENTRICA"},
                                                         {"SCT", "128583004", "Mesenteric vein", "MESENTRICV"},
                                                         {"SCT", "17232002", "Middle cerebral artery", "MCA"},
                                                         {"SCT", "273099000", "Middle hepatic vein", "MIDHEPATICV"},
                                                         {"SCT", "243977002", "Morisons pouch", "MORISONSPOUCH"},
                                                         {"SCT", "123851003", "Mouth", "MOUTH"},
                                                         {"SCT", "102292000", "Muscle of lower limb", ""},
                                                         {"SCT", "30608006", "Muscle of upper limb", ""},
                                                         {"SCT", "74386004", "Nasal bone", ""},
                                                         {"SCT", "360955006", "Nasopharynx", "NASOPHARYNX"},
                                                         {"SCT", "45048000", "Neck", "NECK"},
                                                         {"SCT", "416319003", "Neck, Chest, Abdomen and Pelvis", "NECKCHESTABDPELV"},
                                                         {"SCT", "416152001", "Neck, Chest and Abdomen", "NECKCHESTABDOMEN"},
                                                         {"SCT", "417437006", "Neck and Chest", "NECKCHEST"},
                                                         {"SCT", "45206002", "Nose", "NOSE"},
                                                         {"SCT", "31145008", "Occipital artery", "OCCPITALA"},
                                                         {"SCT", "32114007", "Occipital vein", "OCCIPTALV"},
                                                         {"SCT", "113346000", "Omental bursa", ""},
                                                         {"SCT", "27398004", "Omentum", ""},
                                                         {"SCT", "53549008", "Ophthalmic artery", "OPHTHALMICA"},
                                                         {"SCT", "55024004", "Optic canal", "OPTICCANAL"},
                                                         {"SCT", "363654007", "Orbital structure", "ORBIT"},
                                                         {"SCT", "15497006", "Ovary", "OVARY"},
                                                         {"SCT", "15776009", "Pancreas", "PANCREAS"},
                                                         {"SCT", "69930009", "Pancreatic duct", "PANCREATICDUCT"},
                                                         {"SCT", "110621006", "Pancreatic duct and bile duct systems", "PANCBILEDUCT"},
                                                         {"SCT", "2095001", "Paranasal sinus", ""},
                                                         {"SCT", "91691001", "Parasternal", "PARASTERNAL"},
                                                         {"SCT", "111002", "Parathyroid", "PARATHYROID"},
                                                         {"SCT", "45289007", "Parotid gland", "PAROTID"},
                                                         {"SCT", "64234005", "Patella", "PATELLA"},
                                                         {"SCT", "83330001", "Patent ductus arteriosus", ""},
                                                         {"SCT", "816092008", "Pelvis", "PELVIS"},
                                                         {"SCT", "1231522001", "Pelvis and lower extremities", "PELVISLOWEXTREMT"},
                                                         {"SCT", "282044005", "Penile artery", "PENILEA"},
                                                         {"SCT", "18911002", "Penis", "PENIS"},
                                                         {"SCT", "38864007", "Perineum", "PERINEUM"},
                                                         {"SCT", "8821006", "Peroneal artery", "PERONEALA"},
                                                         {"SCT", "706342009", "Phantom", "PHANTOM"},
                                                         {"SCT", "54066008", "Pharynx", "PHARYNX"},
                                                         {"SCT", "312535008", "Pharynx and larynx", "PHARYNXLARYNX"},
                                                         {"SCT", "78067005", "Placenta", "PLACENTA"},
                                                         {"SCT", "43899006", "Popliteal artery", "POPLITEALA"},
                                                         {"SCT", "32361000", "Popliteal fossa", "POPLITEALFOSSA"},
                                                         {"SCT", "56849005", "Popliteal vein", "POPLITEALV"},
                                                         {"SCT", "32764006", "Portal vein", "PORTALV"},
                                                         {"SCT", "70382005", "Posterior cerebral artery", "PCA"},
                                                         {"SCT", "43119007", "Posterior communicating artery", "POSCOMMA"},
                                                         {"SCT", "128569001", "Posterior medial tributary", ""},
                                                         {"SCT", "13363002", "Posterior tibial artery", "POSTIBIALA"},
                                                         {"SCT", "14944004", "Primitive aorta", ""},
                                                         {"SCT", "91707000", "Primitive pulmonary artery", ""},
                                                         {"SCT", "31677005", "Profunda femoris artery", "PROFFEMA"},
                                                         {"SCT", "23438002", "Profunda femoris vein", "PROFFEMV"},
                                                         {"SCT", "41216001", "Prostate", "PROSTATE"},
                                                         {"SCT", "81040000", "Pulmonary artery", "PULMONARYA"},
                                                         {"SCT", "128584005", "Pulmonary artery conduit", ""},
                                                         {"SCT", "128586007", "Pulmonary chamber of cor triatriatum", ""},
                                                         {"SCT", "122972007", "Pulmonary vein", "PULMONARYV"},
                                                         {"SCT", "128566008", "Pulmonary vein confluence", ""},
                                                         {"SCT", "128567004", "Pulmonary venous atrium", ""},
                                                         {"SCT", "45631007", "Radial artery", "RADIALA"},
                                                         {"SCT", "62413002", "Radius", "RADIUS"},
                                                         {"SCT", "110535000", "Radius and ulna", "RADIUSULNA"},
                                                         {"SCT", "53843000", "Rectouterine pouch", "CULDESAC"},
                                                         {"SCT", "34402009", "Rectum", "RECTUM"},
                                                         {"SCT", "2841007", "Renal artery", "RENALA"},
                                                         {"SCT", "25990002", "Renal pelvis", ""},
                                                         {"SCT", "56400007", "Renal vein", "RENALV"},
                                                         {"SCT", "82849001", "Retroperitoneum", "RETROPERITONEUM"},
                                                         {"SCT", "113197003", "Rib", "RIB"},
                                                         {"SCT", "73829009", "Right atrium", "RATRIUM"},
                                                         {"SCT", "68300000", "Right auricular appendage", ""},
                                                         {"SCT", "69833005", "Right femoral artery", "RFEMORALA"},
                                                         {"SCT", "272998002", "Right hepatic vein", "RHEPATICV"},
                                                         {"SCT", "133946002", "Right hypochondriac region", "RHYPOCHONDRIAC"},
                                                         {"SCT", "37117007", "Right inguinal region", "RINGUINAL"},
                                                         {"SCT", "48544008", "Right lower quadrant of abdomen", "RLQ"},
                                                         {"SCT", "1017211000", "Right lumbar region", "RLUMBAR"},
                                                         {"SCT", "73931004", "Right portal vein", "RPORTALV"},
                                                         {"SCT", "78480002", "Right pulmonary artery", "RPULMONARYA"},
                                                         {"SCT", "50519007", "Right upper quadrant of abdomen", "RUQ"},
                                                         {"SCT", "53085002", "Right ventricle", "RVENTRICLE"},
                                                         {"SCT", "8017000", "Right ventricle inflow", ""},
                                                         {"SCT", "44627009", "Right ventricle outflow tract", ""},
                                                         {"SCT", "39723000", "Sacroiliac joint", "SIJOINT"},
                                                         {"SCT", "54735007", "Sacrum", "SSPINE"},
                                                         {"SCT", "128587003", "Saphenofemoral junction", "SFJ"},
                                                         {"SCT", "362072009", "Saphenous vein", "SAPHENOUSV"},
                                                         {"SCT", "41695006", "Scalp", "SCALP"},
                                                         {"SCT", "79601000", "Scapula", "SCAPULA"},
                                                         {"SCT", "18619003", "Sclera", "SCLERA"},
                                                         {"SCT", "20233005", "Scrotum", "SCROTUM"},
                                                         {"SCT", "42575006", "Sella turcica", "SELLA"},
                                                         {"SCT", "64739004", "Seminal vesicle", "SEMVESICLE"},
                                                         {"SCT", "58742003", "Sesamoid bones of foot", "SESAMOID"},
                                                         {"SCT", "16982005", "Shoulder", "SHOULDER"},
                                                         {"SCT", "60184004", "Sigmoid colon", "SIGMOID"},
                                                         {"SCT", "89546000", "Skull", "SKULL"},
                                                         {"SCT", "30315005", "Small intestine", "SMALLINTESTINE"},
                                                         {"SCT", "2748008", "Spinal cord", "SPINALCORD"},
                                                         {"SCT", "421060004", "Spine", "SPINE"},
                                                         {"SCT", "78961009", "Spleen", "SPLEEN"},
                                                         {"SCT", "22083002", "Splenic artery", "SPLENICA"},
                                                         {"SCT", "35819009", "Splenic vein", "SPLENICV"},
                                                         {"SCT", "7844006", "Sternoclavicular joint", "SCJOINT"},
                                                         {"SCT", "56873002", "Sternum", "STERNUM"},
                                                         {"SCT", "69695003", "Stomach", "STOMACH"},
                                                         {"SCT", "36765005", "Subclavian artery", "SUBCLAVIANA"},
                                                         {"SCT", "9454009", "Subclavian vein", "SUBCLAVIANV"},
                                                         {"SCT", "19695001", "Subcostal", "SUBCOSTAL"},
                                                         {"SCT", "5713008", "Submandibular area", ""},
                                                         {"SCT", "54019009", "Submandibular gland", "SUBMANDIBULAR"},
                                                         {"SCT", "170887008", "Submental", ""},
                                                         {"SCT", "5076001", "Subxiphoid", ""},
                                                         {"SCT", "181349008", "Superficial femoral artery", "SFA"},
                                                         {"SCT", "397364003", "Superficial femoral vein", "SFV"},
                                                         {"SCT", "15672000", "Superficial temporal artery", ""},
                                                         {"SCT", "43863001", "Superior left pulmonary vein", "LSUPPULMONARYV"},
                                                         {"SCT", "42258001", "Superior mesenteric artery", "SMA"},
                                                         {"SCT", "8629005", "Superior right pulmonary vein", "RSUPPULMONARYV"},
                                                         {"SCT", "72021004", "Superior thyroid artery", "SUPTHYROIDA"},
                                                         {"SCT", "48345005", "Superior vena cava", "SVC"},
                                                         {"SCT", "77621008", "Supraclavicular region of neck", "SUPRACLAVICULAR"},
                                                         {"SCT", "11708003", "Suprapubic region", "SUPRAPUBIC"},
                                                         {"SCT", "26493002", "Suprasternal notch", ""},
                                                         {"SCT", "128589000", "Systemic collateral artery to lung", ""},
                                                         {"SCT", "128568009", "Systemic venous atrium", ""},
                                                         {"SCT", "27949001", "Tarsal joint", ""},
                                                         {"SCT", "53620006", "Temporomandibular joint", "TMJ"},
                                                         {"SCT", "40689003", "Testis", "TESTIS"},
                                                         {"SCT", "42695009", "Thalamus", "THALAMUS"},
                                                         {"SCT", "68367000", "Thigh", "THIGH"},
                                                         {"SCT", "49841001", "Third ventricle", "3RDVENTRICLE"},
                                                         {"SCT", "113262008", "Thoracic aorta", "THORACICAORTA"},
                                                         {"SCT", "122495006", "Thoracic spine", "TSPINE"},
                                                         {"SCT", "1217256009", "Thoraco-lumbar spine", "TLSPINE"},
                                                         {"SCT", "43799004", "Thorax", "THORAX"},
                                                         {"SCT", "76505004", "Thumb", "THUMB"},
                                                         {"SCT", "9875009", "Thymus", "THYMUS"},
                                                         {"SCT", "69748006", "Thyroid", "THYROID"},
                                                         {"SCT", "12611008", "Tibia", "TIBIA"},
                                                         {"SCT", "110536004", "Tibia and fibula", "TIBIAFIBULA"},
                                                         {"SCT", "29707007", "Toe", "TOE"},
                                                         {"SCT", "21974007", "Tongue", "TONGUE"},
                                                         {"SCT", "44567001", "Trachea", "TRACHEA"},
                                                         {"SCT", "110726009", "Trachea and bronchus", "TRACHEABRONCHUS"},
                                                         {"SCT", "485005", "Transverse colon", "TRANSVERSECOLON"},
                                                         {"SCT", "61959006", "Truncus arteriosus communis", ""},
                                                         {"SCT", "57850000", "Truncus coeliacus", ""},
                                                         {"SCT", "23416004", "Ulna", "ULNA"},
                                                         {"SCT", "44984001", "Ulnar artery", "ULNARA"},
                                                         {"SCT", "50536004", "Umbilical artery", "UMBILICALA"},
                                                         {"SCT", "90290004", "Umbilical region", "UMBILICAL"},
                                                         {"SCT", "284639000", "Umbilical vein", "UMBILICALV"},
                                                         {"SCT", "40983000", "Upper arm", "UPPERARM"},
                                                         {"SCT", "77831004", "Upper inner quadrant of breast", ""},
                                                         {"SCT", "53120007", "Upper limb", "UPPERLIMB"},
                                                         {"SCT", "76365002", "Upper outer quadrant of breast", ""},
                                                         {"SCT", "431491007", "Upper urinary tract", "UPRURINARYTRACT"},
                                                         {"SCT", "87953007", "Ureter", "URETER"},
                                                         {"SCT", "13648007", "Urethra", "URETHRA"},
                                                         {"SCT", "35039007", "Uterus", "UTERUS"},
                                                         {"SCT", "110639002", "Uterus and fallopian tubes", ""},
                                                         {"SCT", "76784001", "Vagina", "VAGINA"},
                                                         {"SCT", "118375008", "Vascular graft", ""},
                                                         {"SCT", "29092000", "Vein", "VEIN"},
                                                         {"SCT", "34340008", "Venous network", ""},
                                                         {"SCT", "21814001", "Ventricle", ""},
                                                         {"SCT", "85234005", "Vertebral artery", "VERTEBRALA"},
                                                         {"SCT", "110517009", "Vertebral column and cranium", ""},
                                                         {"SCT", "45292006", "Vulva", "VULVA"},
                                                         {"SCT", "74670003", "Wrist joint", "WRIST"},
                                                         {"SCT", "13881006", "Zygoma", "ZYGOMA"},
                                                         {"SCT", "818981001", "Abdomen", "ABDOMEN"},
                                                         {"SCT", "42694008", "All legs", "LEGS"},
                                                         {"SCT", "62555009", "Atlantal-axial joint", "ATLANTOAXIAL"},
                                                         {"SCT", "20292002", "Atlanto-occipital joint", "ATLANTOOCCIPITAL"},
                                                         {"SCT", "89837001", "Bladder", "BLADDER"},
                                                         {"SCT", "82474009", "Calcaneal tubercle", ""},
                                                         {"SCT", "8205005", "Carpus", "CARPUS"},
                                                         {"SCT", "122494005", "Cervical spine", "CSPINE"},
                                                         {"SCT", "1217257000", "Cervico-thoracic spine", "CTSPINE"},
                                                         {"SCT", "816094009", "Chest", "CHEST"},
                                                         {"SCT", "416550000", "Chest and Abdomen", "CHESTABDOMEN"},
                                                         {"SCT", "18149002", "Coccygeal vertrebrae", "TAIL"},
                                                         {"SCT", "71854001", "Colon", "COLON"},
                                                         {"SCT", "82680008", "Digit", "DIGIT"},
                                                         {"UMLS", "C3669027", "Distal phalanx", "DISTALPHALANX"},
                                                         {"SCT", "16953009", "Elbow joint", "ELBOW"},
                                                         {"SCT", "38266002", "Entire body", "WHOLEBODY"},
                                                         {"SCT", "32849002", "Esophagus", "ESOPHAGUS"},
                                                         {"SCT", "71341001", "Femur", "FEMUR"},
                                                         {"SCT", "13190002", "Fetlock of forelimb", "FOREFETLOCK"},
                                                         {"SCT", "113351006", "Fetlock of hindlimb", "HINDFETLOCK"},
                                                         {"SCT", "87342007", "Fibula", "FIBULA"},
                                                         {"SCT", "419176008", "Forefoot", "FOREFOOT"},
                                                         {"SCT", "55060009", "Frontal sinus", "FRONTALSINUS"},
                                                         {"SCT", "416804009", "Hindfoot", "HINDFOOT"},
                                                         {"SCT", "24136001", "Hip joint", "HIP"},
                                                         {"SCT", "85050009", "Humerus", "HUMERUS"},
                                                         {"SCT", "122496007", "Lumbar spine", "LSPINE"},
                                                         {"SCT", "1217253001", "Lumbo-sacral spine", "LSSPINE"},
                                                         {"SCT", "91609006", "Mandible", "JAW"},
                                                         {"SCT", "88176008", "Mandibular dental arch", ""},
                                                         {"SCT", "442274007", "Mandibular incisor teeth", ""},
                                                         {"SCT", "39481002", "Maxillary dental arch", ""},
                                                         {"SCT", "442100006", "Maxillary incisor teeth", ""},
                                                         {"SCT", "36455000", "Metacarpus", "METACARPUS"},
                                                         {"SCT", "280711000", "Metatarsus", "METATARSUS"},
                                                         {"SCT", "2095001", "Nasal sinus", ""},
                                                         {"SCT", "30518006", "Navicular of forefoot", "FORENAVICULAR"},
                                                         {"SCT", "75772009", "Navicular of hindfoot", "HINDNAVICULAR"},
                                                         {"SCT", "363654007", "Orbital structure", "ORBIT"},
                                                         {"SCT", "31329001", "Pastern of forefoot", "FOREPASTERN"},
                                                         {"SCT", "18525008", "Pastern of hindfoot", "HINDPASTERN"},
                                                         {"SCT", "64234005", "Patella", "PATELLA"},
                                                         {"SCT", "816092008", "Pelvis", "PELVIS"},
                                                         {"SCT", "62413002", "Radius", "RADIUS"},
                                                         {"SCT", "110535000", "Radius and ulna", "RADIUSULNA"},
                                                         {"SCT", "54735007", "Sacrum", "SSPINE"},
                                                         {"SCT", "16982005", "Shoulder", "SHOULDER"},
                                                         {"SCT", "89546000", "Skull", "SKULL"},
                                                         {"SCT", "116010006", "Stiffle", "STIFLE"},
                                                         {"SCT", "108371006", "Tarsus", "TARSUS"},
                                                         {"SCT", "122495006", "Thoracic spine", "TSPINE"},
                                                         {"SCT", "1217256009", "Thoraco-lumbar spine", "TLSPINE"},
                                                         {"SCT", "12611008", "Tibia", "TIBIA"},
                                                         {"SCT", "110536004", "Tibia and fibula", "TIBIAFIBULA"},
                                                         {"SCT", "62834003", "Upper gastro-intestinal tract", "UGITRACT"},
                                                         {"SCT", "23416004", "Ulna", "ULNA"},
                                                         {"SCT", "13648007", "Urethra", "URETHRA"},
                                                         {"SCT", "431938005", "Urinary tract", "URINARYTRACT"},
                                                         {"SCT", "53036007", "Wing", "WING"},
                                                         {"SCT", "23451007", "Adrenal gland", "ADRENAL"},
                                                         {"SCT", "70258002", "Ankle joint", "ANKLE"},
                                                         {"SCT", "15825003", "Aorta", "AORTA"},
                                                         {"SCT", "89837001", "Bladder", "BLADDER"},
                                                         {"SCT", "12738006", "Brain", "BRAIN"},
                                                         {"SCT", "76752008", "Breast", "BREAST"},
                                                         {"SCT", "955009", "Bronchus", "BRONCHUS"},
                                                         {"SCT", "60819002", "Buccal region of face", "CHEEK"},
                                                         {"SCT", "80144004", "Calcaneus", "CALCANEUS"},
                                                         {"SCT", "69105007", "Carotid Artery", "CAROTID"},
                                                         {"SCT", "113305005", "Cerebellum", "CEREBELLUM"},
                                                         {"SCT", "71252005", "Cervix", "CERVIX"},
                                                         {"SCT", "51299004", "Clavicle", "CLAVICLE"},
                                                         {"SCT", "64688005", "Coccyx", "COCCYX"},
                                                         {"SCT", "71854001", "Colon", "COLON"},
                                                         {"SCT", "28726007", "Cornea", "CORNEA"},
                                                         {"SCT", "41801008", "Coronary artery", "CORONARYARTERY"},
                                                         {"SCT", "82680008", "Digit", "DIGIT"},
                                                         {"SCT", "38848004", "Duodenum", "DUODENUM"},
                                                         {"SCT", "16953009", "Elbow joint", "ELBOW"},
                                                         {"SCT", "32849002", "Esophagus", "ESOPHAGUS"},
                                                         {"SCT", "66019005", "Extremity", "EXTREMITY"},
                                                         {"SCT", "81745001", "Eye", "EYE"},
                                                         {"SCT", "80243003", "Eyelid", "EYELID"},
                                                         {"SCT", "89545001", "Face", "FACE"},
                                                         {"SCT", "71341001", "Femur", "FEMUR"},
                                                         {"SCT", "87342007", "Fibula", "FIBULA"},
                                                         {"SCT", "7569003", "Finger", "FINGER"},
                                                         {"SCT", "56459004", "Foot", "FOOT"},
                                                         {"SCT", "55060009", "Frontal sinus", "FRONTALSINUS"},
                                                         {"SCT", "28231008", "Gallbladder", "GALLBLADDER"},
                                                         {"SCT", "85562004", "Hand", "HAND"},
                                                         {"SCT", "69536005", "Head", "HEAD"},
                                                         {"SCT", "774007", "Head and Neck", "HEADNECK"},
                                                         {"SCT", "80891009", "Heart", "HEART"},
                                                         {"SCT", "24136001", "Hip joint", "HIP"},
                                                         {"SCT", "85050009", "Humerus", "HUMERUS"},
                                                         {"SCT", "34516001", "Ileum", "ILEUM"},
                                                         {"SCT", "22356005", "Ilium", "ILIUM"},
                                                         {"SCT", "661005", "Jaw region", "JAW"},
                                                         {"SCT", "21306003", "Jejunum", "JEJUNUM"},
                                                         {"SCT", "64033007", "Kidney", "KIDNEY"},
                                                         {"SCT", "10200004", "Liver", "LIVER"},
                                                         {"SCT", "30021000", "Lower leg", "LEG"},
                                                         {"SCT", "39607008", "Lung", "LUNG"},
                                                         {"SCT", "91609006", "Mandible", "JAW"},
                                                         {"SCT", "70925003", "Maxilla", "MAXILLA"},
                                                         {"SCT", "30518006", "Navicular of forefoot", "FORENAVICULAR"},
                                                         {"SCT", "45048000", "Neck", "NECK"},
                                                         {"SCT", "363654007", "Orbital structure", "ORBIT"},
                                                         {"SCT", "15497006", "Ovary", "OVARY"},
                                                         {"SCT", "15776009", "Pancreas", "PANCREAS"},
                                                         {"SCT", "45289007", "Parotid gland", "PAROTID"},
                                                         {"SCT", "64234005", "Patella", "PATELLA"},
                                                         {"SCT", "816092008", "Pelvis", "PELVIS"},
                                                         {"SCT", "18911002", "Penis", "PENIS"},
                                                         {"SCT", "54066008", "Pharynx", "PHARYNX"},
                                                         {"SCT", "62413002", "Radius", "RADIUS"},
                                                         {"SCT", "34402009", "Rectum", "RECTUM"},
                                                         {"SCT", "113197003", "Rib", "RIB"},
                                                         {"SCT", "79601000", "Scapula", "SCAPULA"},
                                                         {"SCT", "18619003", "Sclera", "SCLERA"},
                                                         {"SCT", "20233005", "Scrotum", "SCROTUM"},
                                                         {"SCT", "16982005", "Shoulder", "SHOULDER"},
                                                         {"SCT", "89546000", "Skull", "SKULL"},
                                                         {"SCT", "78961009", "Spleen", "SPLEEN"},
                                                         {"SCT", "56873002", "Sternum", "STERNUM"},
                                                         {"SCT", "53620006", "Temporomandibular joint", "TMJ"},
                                                         {"SCT", "40689003", "Testis", "TESTIS"},
                                                         {"SCT", "68367000", "Thigh", "THIGH"},
                                                         {"SCT", "76505004", "Thumb", "THUMB"},
                                                         {"SCT", "9875009", "Thymus", "THYMUS"},
                                                         {"SCT", "69748006", "Thyroid", "THYROID"},
                                                         {"SCT", "12611008", "Tibia", "TIBIA"},
                                                         {"SCT", "29707007", "Toe", "TOE"},
                                                         {"SCT", "21974007", "Tongue", "TONGUE"},
                                                         {"SCT", "23416004", "Ulna", "ULNA"},
                                                         {"SCT", "40983000", "Upper arm", "ARM"},
                                                         {"SCT", "87953007", "Ureter", "URETER"},
                                                         {"SCT", "13648007", "Urethra", "URETHRA"},
                                                         {"SCT", "35039007", "Uterus", "UTERUS"},
                                                         {"SCT", "76784001", "Vagina", "VAGINA"},
                                                         {"SCT", "45292006", "Vulva", "VULVA"}});

// https://wiki.cancerimagingarchive.net/display/Public/De-identification+Knowledge+Base
nlohmann::json work = nlohmann::json::array({
    {"0008", "0050", "AccessionNumber", "hash"},
    {"0018", "4000", "AcquisitionComments", "keep"},
    {"0040", "0555", "AcquisitionContextSeq", "remove"},
    {"0008", "0022", "AcquisitionDate", "incrementdate"},
    {"0008", "002a", "AcquisitionDateTime", "incrementdatetime"},
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
    {"0018", "1012", "DateOfSecondaryCapture", "incrementdate", "", "createIfMissing"},
    {"0012", "0063", "DeIdentificationMethod", "{Per DICOM PS 3.15 AnnexE}", "", "createIfMissing"},
    {"0012", "0064", "DeIdentificationMethodCodeSequence", "113100/113101/113105/113107/113108/113109/113111", "",
     "createIfMissing"}, // TODO: this has to be written as SQ? We don't need this field if DeIdentificationMethod is there...
    {"0012", "0062", "PatientIdentityRemoved", "YES", "", "createIfMissing"},
    {"0012", "0020", "Clinical Trial Protocol ID", "ProjectName", "", "createIfMissing"},
    {"0012", "0021", "Clinical Trial Protocol Name", "ProjectName", "", "createIfMissing"},
    {"0012", "0040", "Clinical Trial Subject ID", "PatientID", "", "createIfMissing"},
    {"0012", "0050", "Clinical Trial Time Point ID", "EventName", "", "createIfMissing"},
    {"0012", "0051", "Clinical Trial Time Point Description", "EventName", "", "createIfMissing"},
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
    {"0008", "0080", "InstitutionName", "ProjectName", "", "createIfMissing"},
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
    {"0010", "0020", "PatientID", "Re-Mapped", "", "createIfMissing"},
    {"0038", "0400", "PatientInstitutionResidence", "remove"},
    {"0010", "0050", "PatientInsurancePlanCodeSeq", "remove"},
    {"0010", "1060", "PatientMotherBirthName", "remove"},
    {"0010", "0010", "PatientName", "Re-Mapped", "", "createIfMissing"},
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
    {"0040", "0244", "PerformedProcedureStepStartDate", "incrementdate"},
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
    {"0018", "1078", "Radiopharmaceutical Start DateTime", "incrementdatetime"},
    {"0018", "1079", "Radiopharmaceutical Stop DateTime", "incrementdatetime"},
    {"0040", "2001", "ReasonForImagingServiceRequest", "keep"},
    {"0032", "1030", "ReasonforStudy", "keep"},
    {"0400", "0402", "RefDigitalSignatureSeq", "remove"},
    {"3006", "0024", "ReferencedFrameOfReferenceUID", "hashuid+PROJECTNAME"},
    {"0038", "0004", "ReferencedPatientAliasSeq", "remove"},
    {"0008", "0092", "ReferringPhysicianAddress", "remove"},
    {"0008", "0090", "ReferringPhysicianName", "empty", "", "createIfMissing"},
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
    {"0008", "0020", "StudyDate", "incrementdate", "", "createIfMissing"},
    {"0008", "1030", "StudyDescription", "keep"},
    {"0020", "0010", "StudyID", "hash"},
    {"0032", "0012", "StudyIDIssuer", "remove"},
    {"0020", "000d", "StudyInstanceUID", "hashuid+PROJECTNAME"},
    {"0008", "0030", "StudyTime", "keep", "", "createIfMissing"},
    {"0020", "0200", "SynchronizationFrameOfReferenceUID", "hashuid"},
    {"0040", "db0d", "TemplateExtensionCreatorUID", "hashuid"},
    {"0040", "db0c", "TemplateExtensionOrganizationUID", "hashuid"},
    {"4000", "4000", "TextComments", "remove"},
    {"2030", "0020", "TextString", "remove"},
    {"0008", "0201", "TimezoneOffsetFromUTC", "remove"},
    {"0088", "0910", "TopicAuthor",                       "remove"},
    {"0088", "0912", "TopicKeyWords",                       "remove"},
    {"0088", "0906", "TopicSubject",                        "remove"},
    {"0088", "0904", "TopicTitle",                          "remove"},
    {"0008", "1195", "TransactionUID",                      "hashuid"},
    {"0013", "1011", "TrialName",                           "PROJECTNAME"},
    {"0040", "a124", "UID",                                 "hashuid"},
    {"0040", "a088", "VerifyingObserverIdentificationCodeSeq", "remove"},
    {"0040", "a075", "VerifyingObserverName",               "empty"},
    {"0040", "a073", "VerifyingObserverSequence",           "remove"},
    {"0040", "a027", "VerifyingOrganization",               "remove"},
    {"0038", "4000", "VisitComments",                       "keep"},
    {"0033", "1013", "MITRA OBJECT UTF8 ATTRIBUTES 1.0",/*"SomeSiemensMITRA",*/                    "remove"},
    {"0033", "1016", "MITRA OBJECT UTF8 ATTRIBUTES 1.0",/*"SomeSiemensMITRA",*/                    "remove"},
    {"0033", "1019", "MITRA OBJECT UTF8 ATTRIBUTES 1.0",/*"SomeSiemensMITRA",*/                    "remove"},
    {"0033", "101c", "MITRA OBJECT UTF8 ATTRIBUTES 1.0",/*"SomeSiemensMITRA",*/                    "remove"},
    {"0009", "1001", "SectraIdentRequestID",                "remove"},     // if 0009,0010 is SECTRA_Ident_01
    {"0009", "1002", "SectraIdentExaminationID",            "remove"}, // if 0009,0010 is SECTRA_Ident_01
    {"0071", "1022", "SIEMENS MED PT",                      "incrementdatetime"},
});


std::map<std::string, int> workCache;
void createWorkCache() {
  for (int i = 0; i < work.size(); i++) {
    std::string key = std::string(work[i][0]) + std::string(work[i][1]);
    if (workCache.find(key) == workCache.end()) {
      // add this entry
      workCache.insert(std::pair<std::string, int>{key,i});
    }
  }
}

std::string limitToMaxLength(gdcm::Tag t, std::string& str_in, const gdcm::DataSet& ds) {
  const gdcm::DataElement& de = ds.GetDataElement(t);
  gdcm::VR vr = de.GetVR();
  std::string VRName = gdcm::VR::GetVRString(vr);

  if (VRName == "??") // don't know, do nothing
    return std::string(str_in);

  /*if (str_in.size()%2!=0) { // odd length for this value, make even length by adding null or space
    if (VRName != "UI") { 
      str_in += " ";
    } else { // but what about binary, this is only if its isASCII
      str_in += '\0';
    }
    }*/
  
  std::unordered_map<std::string, uint32_t> max_lengths = {
    {"AE", 16},
    {"AS", 4},
    {"AT", 4},
    {"CS", 16},
    {"DA", 8},
    {"DS", 16},
    {"DT", 26},
    {"FL", 4},
    {"FD", 8},
    {"IS", 12},
    {"LO", 64},
    {"LT", 10240},
    {"SH", 16},
    {"SL", 4},
    {"SS", 2},
    {"ST", 1024},
    {"TM", 16},
    {"UI", 64},
    {"UL", 4},
    {"US", 2}
  };

  auto max_length_it = max_lengths.find(VRName);
  if (max_length_it == max_lengths.end())
    return std::string(str_in); // do nothing

  // some elements need a space to get to even length, some need a null byte
  // see: https://dicom.nema.org/dicom/2013/output/chtml/part05/sect_6.2.html

  uint32_t max_l = max_length_it->second;
  if (max_l == 0)
    return std::string(str_in); // should never happen

  if (str_in.length() > max_l) {
    std::string str_limited = str_in.substr(0, max_l);
    if (debug_level > 2)
      fprintf(stderr, "Warning: tag (%04x,%04x) value too long (%zu), max: %u for VR: %s, will be truncated.\n",
              t.GetGroup(), t.GetElement(), str_in.length(), max_l, gdcm::VR::GetVRString(vr));
    return str_limited;
  }

  return std::string(str_in);
}

/*std::string limitToMaxLength(gdcm::Tag t, std::string str_in, gdcm::DataSet &ds) {
  // what is the value representation?
  const gdcm::DataElement& de = ds.GetDataElement( t );
  gdcm::VR vr = de.GetVR();
  std::string VRName = gdcm::VR::GetVRString(vr);
  if (VRName == "??") // don't know, do nothing
    return str_in;
  uint32_t max_l = 0;
  if (VRName == "AE")
    max_l = 16;
  else if (VRName == "AS")
    max_l = 4;
  else if (VRName == "AT")
    max_l = 4;
  else if (VRName == "CS")
    max_l = 16;
  else if (VRName == "DA")
    max_l = 8;
  else if (VRName == "DS")
    max_l = 16;
  else if (VRName == "DT")
    max_l = 26;
  else if (VRName == "FL")
    max_l = 4;
  else if (VRName == "FD")
    max_l = 8;
  else if (VRName == "IS")
    max_l = 12;
  else if (VRName == "LO")
    max_l = 64;
  else if (VRName == "LT")
    max_l = 10240;
  else if (VRName == "SH")
    max_l = 16;
  else if (VRName == "SL")
    max_l = 4;
  else if (VRName == "SS")
    max_l = 2;
  else if (VRName == "ST")
    max_l = 1024;
  else if (VRName == "TM")
    max_l = 16;
  else if (VRName == "UI")
    max_l = 64;
  else if (VRName == "UL")
    max_l = 4;
  else if (VRName == "US")
    max_l = 2;
  else
    return str_in; // do nothing
  if (max_l == 0)
    return str_in; // should never happen
  
  // check if length of str is longer than l
  unsigned ll = str_in.length();
  if (ll > max_l) {
    fprintf(stderr, "Warning: tag value too long (%d), max: %d for VR: %s, will be truncated.\n", ll, max_l, gdcm::VR::GetVRString(vr));
    std::string str_limited(str_in, 0, max_l);
    return str_limited;
  }
  // no change
  return str_in;
}*/

// The TeraRecon workstation rejects images with StudyInstanceUIDs that
// do not contains some dots and numbers only. We should be closer to the
// standard if we start with our organizational root.
//
// We still do not fulfil the standard (http://dicom.nema.org/dicom/2013/output/chtml/part05/chapter_9.html)
// because only 0-9 characters are allowed.

// We have a second case for UIDs outside the standard creating problems.
// The Screenpoint software also tests for the standard on UIDs before the
// any processing is done.

// toDec() stupid attempt because 0-5 will be more often in the data compared to 6-9
std::string toDec(SHA256::Byte *data, int size) {
	std::string ret="";
	const char *decdigit="0123456789012345";
	for (int i=0;i<size;i++) {
		ret+=decdigit[(data[i]>>4)&0xf]; // high 4 bits
		ret+=decdigit[(data[i]   )&0xf]; // low 4 bits
	}
	return ret;
}

std::string betterUID(std::string val, bool old_style_uid=false) {
  std::string prefix = "1.3.6.1.4.1.45037"; // organizational prefix for us
  std::string hash = "";  
  if (old_style_uid) { // hexadecimal characters in UID (against standard for DICOM UIDs!)
    hash = SHA256::digestString(val).toHex();
  } else { // new style replacing alphas with numeric characters
    SHA256::digest a = SHA256::digestString(val);
    hash = toDec(a.data, a.size);
  }
  std::string phash = prefix + "." + hash;
  return phash.substr(0,63); // bummer: this truncates our hash value, should be 64
}

// A date calculation using std::chrono. This function requires at least c++20!
void addDays(struct sdate &date1, int days) {

  // try this with chrono instead
  std::chrono::year_month_day _ymd(std::chrono::year(date1.y), std::chrono::month(date1.m), std::chrono::day(date1.d));
  // fprintf(stdout, "%d %d %d\n", static_cast<int>(_ymd.year()), static_cast<unsigned>(_ymd.month()), static_cast<unsigned>(_ymd.day()));
  // add some days
  _ymd = std::chrono::sys_days{_ymd} + std::chrono::days{days};
  // fprintf(stdout, "42 days later: %d %d %d\n", static_cast<int>(_ymd.year()), static_cast<unsigned>(_ymd.month()), static_cast<unsigned>(_ymd.day()));
  date1.y = static_cast<int>(_ymd.year());
  date1.m = static_cast<unsigned>(_ymd.month());
  date1.d = static_cast<unsigned>(_ymd.day());
  return;
}



// if true it indicates that some work was done
bool applyWork(gdcm::DataElement de,
         gdcm::Anonymizer &anon,
	       gdcm::DataSet &ds,
	       int work_idx,
	       threadparams *params,
	       const std::string trueStudyInstanceUID,
	       const std::string filename,
	       std::string &filenamestring,
	       std::string &seriesdirname) {
  gdcm::File &fileToAnon = anon.GetFile();
  //gdcm::DataSet &ds = fileToAnon.GetDataSet();
  
  gdcm::StringFilter sf;
  sf.SetFile(fileToAnon);
  
  gdcm::MediaStorage ms;
  ms.SetFromFile(fileToAnon);
  
  //  for (int i = 0; i < work.size(); i++) {
  // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
  std::string tag1(work[work_idx][0]);
  std::string tag2(work[work_idx][1]);
  std::string which(work[work_idx][2]);
  std::string what("replace");
  bool regexp = false;
  if (work[work_idx].size() > 3) {
    what = work[work_idx][3];
  }
  int a = strtol(tag1.c_str(), NULL, 16);
  int b = strtol(tag2.c_str(), NULL, 16);

  gdcm::Tag hTag(a,b); // either hTag or phTag, better to use a union here
  gdcm::PrivateTag phTag;
  bool isPrivateTag = false;
  if (hTag.IsPrivate()) {
    phTag = gdcm::PrivateTag(a,b,which.c_str()); // 0x71,0x22, "SIEMENS MED PT"
    isPrivateTag = true;
    //fprintf(stderr, "looking now for a PRIVATE TAG AS %04x,%04x %s what: %s isPrivateTag: %s\n", a, b, which.c_str(), what.c_str(), isPrivateTag?"private":"public");
  }
  
  if (which == "DeIdentificationMethodCodeSequence")
    return false; // already handeled above, nothing is done
  
  if (work[work_idx].size() > 4 && work[work_idx][4] == "regexp") {
    regexp = true;
    // as a test print out what we got
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      const gdcm::ByteValue *bv4 = de1.GetByteValue();
      char dat[256];
      
      
      std::string val = sf.ToString(hTag);
      std::string ns("");
      try {
        std::regex re(what);
        std::smatch match;
        if (std::regex_search(val, match, re) && match.size() > 1) {
          for (int j = 1; j < match.size(); j++) {
            ns += match.str(j) + std::string(" ");
          }
        } else {
          ns = std::string("FIONA: no match on regular expression");
        }
      } catch (std::regex_error &e) {
        if (debug_level > 0)
          fprintf(stderr, "ERROR: regular expression match failed on %s,%s which: %s what: %s old: %s new: %s\n", tag1.c_str(), tag2.c_str(), which.c_str(),
            what.c_str(), val.c_str(), ns.c_str());
      }
      // fprintf(stdout, "show: %s,%s which: %s what: %s old: %s new: %s\n", tag1.c_str(), tag2.c_str(), which.c_str(), what.c_str(), val.c_str(),
      // ns.c_str());
      ns = limitToMaxLength(hTag, ns, ds);
      de1.SetByteValue( ns.c_str(), (uint32_t)ns.size() );
      ds.Replace( de1 );
      // anon.Replace(isPrivateTag?phTag:hTag, limitToMaxLength(hTag, ns, ds).c_str());
    }
    return true;
  }
  if (which == "BlockOwner" && what != "replace") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, what, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (which == "ProjectName" || which == "PROJECTNAME") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, params->projectname, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (which == "PatientID" || which == "PATIENTID") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, params->patientid, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "ProjectName" || what == "PROJECTNAME") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, params->projectname, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "PatientID" || what == "PATIENTID") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, params->patientid, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "EventName" || what == "EVENTNAME") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, params->eventname, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (which == "BodyPartExamined" && what == "BODYPART") {
    // allow all allowedBodyParts, or set to BODYPART
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      //        if (ds.FindDataElement(hTag)) {
      std::string input_bodypart = sf.ToString(hTag);
      bool found = false;
      for (int b_idx = 0; b_idx < allowedBodyParts.size(); b_idx++) {
        // what is the current value in this tag?
        // could we have a space at the end of input_bodypart?
        std::string allowedBP = allowedBodyParts[b_idx][3];
        if (allowedBP.size() % 2 == 1) { // we need even length strings for comparisson
          allowedBP += " ";
        }
        // fprintf(stdout, "body parts: \"%s\" \"%s\"\n", input_bodypart.c_str(), allowedBP.c_str());
        if (input_bodypart.compare(allowedBP) == 0) {
          // allowed string, keep it
          found = true;
          break;
        }
      }
      if (found)
        return false;
    }
    // set to empty
    if (debug_level > 2) {
      fprintf(stdout, "unknown body part, replace with BODYPART\n"); 
    }
    gdcm::DataElement de1 = ds.GetDataElement( hTag );
    std::string val("BODYPART");
    de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
    ds.Replace( de1 );
    // if we do not find it we need to do something? 
    return true;
  }
  
  if (what == "replace") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, which, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "remove") {
    if (hTag.IsPrivate()) {
      gdcm::PrivateTag phTag = gdcm::PrivateTag(a,b,which.c_str()); // this will only work if the 0010 entry string in which is correct
      const gdcm::DataElement &ddee = ds.GetDataElement(phTag);
      return ds.Remove( ddee.GetTag() ) == 1;
    }
    return false;
  }
  if (what == "empty") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val("");
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "hashuid+PROJECTNAME") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      const gdcm::ByteValue *bv4 = de1.GetByteValue();
      
      std::string val("");
      if (bv4) {
        val = std::string(bv4->GetPointer(), bv4->GetLength() );
      } else {
        val = sf.ToString(hTag); // does not seem to work inside a sequence, but is this really needed?
      }
      // std::string val = sf.ToString(hTag); // this is problematic - we get the first occurance of this tag, not nessessarily the root tag
      //std::string hash = SHA256::digestString(val + params->projectname).toHex();
      std::string hash = betterUID(val + params->projectname, params->old_style_uid);
      if (which == "SOPInstanceUID") // keep a copy as the filename for the output
        filenamestring = hash.c_str();
      
      if (which == "SeriesInstanceUID")
        seriesdirname = hash.c_str();
      
      if (which == "StudyInstanceUID") {
        // fprintf(stdout, "%s %s ?= %s\n", filename, val.c_str(), trueStudyInstanceUID.c_str());
        if (trueStudyInstanceUID != val) { // in rare cases we will not get the correct tag from sf.ToString, instead use the explicit loop over the root tags
          val = trueStudyInstanceUID;
          // hash = SHA256::digestString(val + params->projectname).toHex();
          hash = betterUID(val + params->projectname, params->old_style_uid);
        }
        // we want to keep a mapping of the old and new study instance uids
        params->byThreadStudyInstanceUID.insert(std::pair<std::string, std::string>(val, hash)); // should only add this pair once
      }
      if (which == "SeriesInstanceUID") {
        // we want to keep a mapping of the old and new study instance uids
        std::string key(val);
        std::string value(hash);
        if (key.length() > 1 && key[key.length()-1] == '\0') {
          std::string::iterator it = key.end() -1;
          key.erase(it);
        }
        if (value.length() > 1 && value[value.length()-1] == '\0') {
          std::string::iterator it = value.end() -1;
          value.erase(it);
        }
        params->byThreadSeriesInstanceUID.insert(std::pair<std::string, std::string>(key, value)); // should only add this pair once
      }
      
      //if (ds.FindDataElement(gdcm::Tag(a, b)))
      hash = limitToMaxLength(hTag, hash, ds);
      // SetByteValue will complain if we try to add an odd length hash
      // but if we write a UID with a space we will get complains later if we want to read them... hmm..
      //if (hash.size()%2!=0)
      //  hash += " ";
      
      de1.SetByteValue( hash.c_str(), (uint32_t)hash.size() );
      ds.Replace( de1 );
      
      // anon.Replace(hTag, limitToMaxLength(hTag, hash, ds).c_str());
      // this does not replace elements inside sequences
      return true;
    }
    return false;
  }
  if (what == "hashuid" || what == "hash") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      const gdcm::ByteValue *bv4 = de1.GetByteValue();
      std::string val("");
      if (bv4) {
        val = std::string(bv4->GetPointer(), bv4->GetLength() );
      } else {
        val = sf.ToString(hTag); // does not seem to work inside a sequence, but is this really needed?
      }
      
      // Question: What happens if the string exists and is empty? In that case we get the same hash value for
      // studies that should be different (PACS wants to have unique numbers). Lets check if that is the case.
      // Question: What if the string is not empty but contains a string that is not unique (like "1"). In that
      // case the PACS might assume that the request id is the same, but the patient info does not match resulting
      // in a mismatch error.
      // For now we replace the StudyID with the hash of the StudyInstanceUID - ALWAYS.
      if (which == "StudyID") {
        // if this is the case replace the StudyID with the hash from the StudyInstanceUID
        val = trueStudyInstanceUID + params->projectname;
        // val = trueStudyInstanceUID;
        //fprintf(stderr, "WARNING: OUR StudyID tag was empty, now it is: \"%s\"\n", val.c_str());
      }
      
      std::string hash = "";
      if (params->old_style_uid) {
        hash = SHA256::digestString(val).toHex();
      } else {
        SHA256::digest a = SHA256::digestString(val);
        hash = toDec(a.data, a.size);            
      }
      
      if (which == "SOPInstanceUID") // keep a copy as the filename for the output
        filenamestring = hash.c_str();
      
      if (which == "SeriesInstanceUID")
        seriesdirname = hash.c_str();
      
      if (which == "SeriesInstanceUID") {
        // we want to keep a mapping of the old and new study instance uids
        std::string key(val);
        std::string value(hash);
        if (key.length() > 1 && key[key.length()-1] == '\0') {
          std::string::iterator it = key.end() -1;
          key.erase(it);
        }
        if (value.length() > 1 && value[value.length()-1] == '\0') {
          std::string::iterator it = value.end() -1;
          value.erase(it);
        }
        params->byThreadSeriesInstanceUID.insert(std::pair<std::string, std::string>(key, value)); // should only add this pair once
      }
      
      if (which == "StudyInstanceUID") {
        if (trueStudyInstanceUID != val) { // in rare cases we will not get the correct tag from sf.ToString, instead use the explicit loop over the root tags
          // fprintf(stdout, "True StudyInstanceUID is not the same as ToString one: %s != %s\n", val.c_str(), trueStudyInstanceUID.c_str());
          val = trueStudyInstanceUID;
          if (what == "hashuid") { // with root
            hash = betterUID(val);
          } else { // if we can use the hash instead, no root infront
            if (params->old_style_uid) {
              hash = SHA256::digestString(val).toHex();
            } else {
              SHA256::digest a = SHA256::digestString(val);
              hash = toDec(a.data, a.size);
            }
          }
        }
      }
      
      hash = limitToMaxLength(hTag, hash, ds);
      de1.SetByteValue( hash.c_str(), (uint32_t)hash.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "keep") {
    // so we do nothing...
    return false;
  }
  if (what == "incrementdate") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      int nd = params->dateincrement;
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      const gdcm::ByteValue *bv4 = de1.GetByteValue();
      
      std::string val("");
      if (bv4) {
        val = std::string(bv4->GetPointer(), bv4->GetLength() );
        //fprintf(stdout, "VALUE from bv4 :  \"%s\" length: %ud\n", val.c_str(), (unsigned int)bv4->GetLength());
      } else {
        val = sf.ToString(hTag); // does not seem to work inside a sequence, but is this really needed?
      }
      
      // parse the date string YYYYMMDD
      struct sdate date1;
      if (sscanf(val.c_str(), "%04ld%02ld%02ld", &date1.y, &date1.m, &date1.d) == 3) {
        // replace with added value
        addDays(date1, nd);
        //long c = gday(date1) + nd;
        //struct sdate date2 = dtf(c);
        char dat[256];
        snprintf(dat, 256, "%04ld%02ld%02ld", date1.y, date1.m, date1.d);
        //fprintf(stdout, "found a date (%04x,%04x): %s, replace with date: %s\n", a, b, val.c_str(), dat);
        // fprintf(stdout, "found a date : %s, replace with date: %s\n",
        // val.c_str(), dat);
        
        de1.SetByteValue( dat, (uint32_t)strlen(dat) );
        ds.Replace( de1 );
        //anon.Replace(hTag, limitToMaxLength(hTag, std::string(dat), ds).c_str());
      } else {
        // could not read the date here, just remove instead
        // fprintf(stdout, "Warning: could not parse a date (\"%s\", %04o,
        // %04o, %s) in %s, remove field instead...\n", val.c_str(), a, b,
        // which.c_str(), filename);
        
        // The issue with empty dates is that we cannot get those back from the research PACS, we should instead use some
        // default dates to cover these cases. What is a good date range for this? Like any date in a specific year?
        // This is true for the StudyDate only. So we can keep the other dates empty. Strange otherwise if there are multiple dates
        // and some had values (will be advanced) and some where empty and get the default dates.
        if (which == "StudyDate") {
          std::string fixed_year("1970");
          int variable_month = (rand() % 12) + 1;
          int day = 1;
          char dat[256];
          snprintf(dat, 256, "%s%02d%02d", fixed_year.c_str(), variable_month, day);
          // fprintf(stderr, "Warning: no date could be parsed in \"%s\" so there is no shifted date, use random date instead.\n", val.c_str());
          de1.SetByteValue( dat, (uint32_t)strlen(dat) );
          ds.Replace( de1 );
        } else {
          // keep them empty
          char dat[1] = {'\0'};
          de1.SetByteValue( dat, (uint32_t)strlen(dat) );
          ds.Replace( de1 );
        }
        //anon.Replace(hTag, dat);
      }
      return true;
    }
    return false;
  }
  if (what == "incrementdatetime") {
    //fprintf(stderr, "FOUND an increemntdatetime field\n");fflush(stderr);
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      //fprintf(stderr, "inside find data element\n");
      int nd = params->dateincrement;
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      const gdcm::ByteValue *bv4 = de1.GetByteValue();
      
      //if ( de1.IsEmpty() ) {
      //  fprintf(stdout, "de1 is empty\n");
      //}
      
      /*if ( de1.GetVL() ) {
	fprintf(stdout, "got a value length\n");
	const gdcm::Value& v = de1.GetValue();
	const gdcm::ByteValue &bv = dynamic_cast<const gdcm::ByteValue&>(v);
	gdcm::Element<gdcm::VR::DT,1> e;
	const void *array = bv.GetVoidPointer();
	//memcpy( (void*)(&e), array, e.GetLength() * sizeof( gdcm::VRToType<gdcm::VR::DT>::Type) );
	}*/
      std::string val("");
      if (bv4) {
        val = std::string(bv4->GetPointer(), bv4->GetLength() );
	//fprintf(stdout, "VALUE from bv4 :  \"%s\" length: %ud\n", val.c_str(), (unsigned int)bv4->GetLength());
      } else {
        val = sf.ToString(hTag); // does not seem to work inside a sequence, but is this really needed?
      }
      
      //std::string val = sf.ToString(hTag); // does not seem to work inside a sequence
      // parse the date string YYYYMMDDHHMMSS
      struct sdate date1;
      char t[245];
      // based on the standard components of DT can be empty (null components), but we already have a YYYY
      int numParsedDateObjects = sscanf(val.c_str(), "%04ld%02ld%02ld%s", &date1.y, &date1.m, &date1.d, t);
      if (numParsedDateObjects == 4) {
	
        // try this with chrono instead
        addDays(date1, nd);
        
        //long c = gday(date1) + nd;
        //struct sdate date2 = dtf(c);
        char dat[256];
        // TODO: ok, there are valid DT fields that only contain a year or only a year and a month but no day
        snprintf(dat, 256, "%04ld%02ld%02ld%s%s", date1.y, date1.m, date1.d, t, (((strlen(t)%2)==0)?"":" "));
        //fprintf(stdout, "found a date (%04x,%04x): %s, replace with date: %s\n", a, b, val.c_str(), dat);
        de1.SetByteValue( dat, (uint32_t)strlen(dat) );
        ds.Replace( de1 );
	
      } else if ( numParsedDateObjects == 3) { // assume that t is empty
        addDays(date1, nd);
	
        // replace with added value
        // long c = gday(date1) + nd;
        //struct sdate date2 = dtf(c);
        char dat[256];
        // TODO: ok, there are valid DT fields that only contain a year or only a year and a month but no day
        snprintf(dat, 256, "%04ld%02ld%02ld", date1.y, date1.m, date1.d);
        if (debug_level > 2)
          fprintf(stdout, "found a date (%04x,%04x): %s, replace with date: %s\n", a, b, val.c_str(), dat);
        de1.SetByteValue( dat, (uint32_t)strlen(dat) );
        ds.Replace( de1 );
            } else if ( numParsedDateObjects == 2) { // assume that t is empty
        // replace with added value
        date1.d = 1;
        addDays(date1, nd);
        
        //long c = gday(date1) + nd;
        //struct sdate date2 = dtf(c);
        char dat[256];
        // TODO: ok, there are valid DT fields that only contain a year or only a year and a month but no day
        snprintf(dat, 256, "%04ld%02ld", date1.y, date1.m);
        if (debug_level > 2)
          fprintf(stdout, "found a date (%04x,%04x): %s, replace with date: %s\n", a, b, val.c_str(), dat);
        de1.SetByteValue( dat, (uint32_t)strlen(dat) );
        ds.Replace( de1 );
            } else if ( numParsedDateObjects == 1) { // assume that t is empty
        // replace with added value
        date1.d = 1;
        date1.m = 1;
        addDays(date1, nd);
        //long c = gday(date1) + nd;
        //struct sdate date2 = dtf(c);
        char dat[256];
        // TODO: ok, there are valid DT fields that only contain a year or only a year and a month but no day
        snprintf(dat, 256, "%04ld", date1.y);
        if (debug_level > 2)
          fprintf(stdout, "found a date (%04x,%04x): %s, replace with date: %s\n", a, b, val.c_str(), dat);
        de1.SetByteValue( dat, (uint32_t)strlen(dat) );
        ds.Replace( de1 );
      } else {
        // could not read the date here, just remove instead
        if (debug_level > 2)
          fprintf(stdout, "Warning: could not parse date (\"%s\", %04x,%04x, %s) in %s, remove field instead...\n", val.c_str(), a, b,which.c_str(), filename.c_str());
        
        // TODO: We should try harder here. The day and month might be missing components
        // and we still have a DT field that is valid (null components).
        char dat[1] = {'\0'};
        de1.SetByteValue( dat, (uint32_t)strlen(dat) );
        ds.Replace( de1 );
        // anon.Replace(hTag, "");
      }
      return true;
    }
    return false;
  }
  if (what == "YES") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      const gdcm::ByteValue *bv4 = de1.GetByteValue();
      /*std::string val("");
      if (bv4) {
      val = std::string(bv4->GetPointer(), bv4->GetLength() );
      } else {
      val = sf.ToString(hTag); // does not seem to work inside a sequence, but is this really needed?
      }*/
      char dat[5];
      snprintf(dat, 5, "YES ");
      de1.SetByteValue( dat, (uint32_t)strlen(dat) );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "MODIFIED") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      const gdcm::ByteValue *bv4 = de1.GetByteValue();
      /*std::string val("");
      if (bv4) {
      val = std::string(bv4->GetPointer(), bv4->GetLength() );
      } else {
      val = sf.ToString(hTag); // does not seem to work inside a sequence, but is this really needed?
      }*/
      char dat[9];
      snprintf(dat, 9, "MODIFIED");
      de1.SetByteValue( dat, (uint32_t)strlen(dat) );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "PROJECTNAME") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, params->projectname, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  if (what == "SITENAME") {
    if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
      gdcm::DataElement de1 = ds.GetDataElement( hTag );
      std::string val = limitToMaxLength(hTag, params->sitename, ds);
      de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
      ds.Replace( de1 );
      return true;
    }
    return false;
  }
  // Some entries have Re-Mapped, that could be a name on the command line or,
  // by default we should hash the id
  // fprintf(stdout, "Warning: set to what: %s %s which: %s what: %s\n", tag1.c_str(), tag2.c_str(), which.c_str(), what.c_str());
  // fallback, if everything fails we just use the which and set that's field value
  if (isPrivateTag?ds.FindDataElement(phTag):ds.FindDataElement(hTag)) {
    gdcm::DataElement de1 = ds.GetDataElement( hTag );
    std::string val = limitToMaxLength(hTag, what, ds);
    if ( val.size()%2 != 0 )
      val += " ";
    de1.SetByteValue( val.c_str(), (uint32_t)val.size() );
    ds.Replace( de1 );
    return true;
  }
  return false;
}

// new attempt to anonymize - including sequences
// example is from gdcmAnonymizer.cxx:
//   static bool Anonymizer_RemoveRetired(File const &file, DataSet &ds)
static bool AnonymizeBasedOnWork(gdcm::File const &file, gdcm::DataSet &ds, const std::string trueStudyInstanceUID, threadparams *params, std::string &filenamestring, std::string &seriesdirname, int level) {
  //static const gdcm::Global &g = gdcm::GlobalInstance;
  //static const gdcm::Dicts &dicts = g.GetDicts();
  //static const gdcm::Dict &pubdict = dicts.GetPublicDict();

  std::string spaces(level, ' ');
  char buf1[16];
  char buf2[16];

  gdcm::DataSet::Iterator it = ds.Begin();
  for ( ; it != ds.End(); ) {
    const gdcm::DataElement &de1 = *it;
    const gdcm::Tag ttt = de1.GetTag();
    // std::set::erase invalidate iterator, so we need to make a copy first:
    gdcm::DataSet::Iterator dup = it;
    if (debug_level > 2)
      fprintf(stdout, "%s  0x%04x,0x%04x advance in %zu, %s level: %d\n", spaces.c_str(), ttt.GetGroup(), ttt.GetElement(), ds.Size(), filenamestring.c_str(), level); fflush(stdout);
    ++it;

    const gdcm::DataElement &de = *dup;
    gdcm::Tag tt = de.GetTag(); // this is the current tag in this nested sequence
    if (debug_level > 2) {
      fprintf(stdout, "%s  %04x,%04x data element\n", spaces.c_str(), tt.GetGroup(), tt.GetElement());fflush(stdout);
    }
    
    gdcm::VR vr = gdcm::DataSetHelper::ComputeVR(file, ds, de.GetTag() );
    if ( vr.Compatible(gdcm::VR::SQ) ) {
      gdcm::SmartPointer<gdcm::SequenceOfItems> sq = de.GetValueAsSQ();
      if ( sq ) {
        gdcm::SequenceOfItems::SizeType n = sq->GetNumberOfItems();
        for ( gdcm::SequenceOfItems::SizeType i = 1; i <= n; i++) { // items start counting at 1
          gdcm::Item &item = sq->GetItem( i );
          gdcm::DataSet &nested = item.GetNestedDataSet();
          AnonymizeBasedOnWork( file, nested, trueStudyInstanceUID, params, filenamestring, seriesdirname, level+4 );
        }
        gdcm::DataElement de_dup = *dup;
        de_dup.SetValue( *sq );
        de_dup.SetVLToUndefined(); // FIXME
        ds.Replace( de_dup );
      }
    } else {
      // not a sequence, so anonymize this data element
      const std::string filename("unknown, inside sequence");
      // we need an anon 
      gdcm::Anonymizer anon;
      anon.SetFile(file);
      
      // We would like to replace this loop. Should be a lookup only
      int a = tt.GetGroup();
      int b = tt.GetElement();
      snprintf(buf1, 16, "%04x", a);
      snprintf(buf2, 16, "%04x", b);
      std::string key = std::string(buf1) + std::string(buf2);
      if (workCache.find(key) != workCache.end()) {
        // found an entry for this group/element in the cache, extract index work[wi]
        int wi = workCache.find(key)->second;
        // we want to anonymize the current DataElement de, not all of them
        bool somethingDone = applyWork(de, anon, ds, wi, params, trueStudyInstanceUID, filename, filenamestring, seriesdirname);
        if (debug_level > 2 && somethingDone) {
          fprintf(stdout, "%s   did something on tag %04x,%04x\n", spaces.c_str(), tt.GetGroup(), tt.GetElement());
        }
      }
/*      for (int wi = 0; wi < work.size(); wi++) {
        std::string tag1(work[wi][0]);
        std::string tag2(work[wi][1]);
        std::string which(work[wi][2]);
        std::string what("replace");
        //bool regexp = false; // if we find a regular expression, only retain the entries that are capturing groups (separated by a space)
        if (work[wi].size() > 3) {
          what = work[wi][3];
        }
        //if (work[wi].size() > 4 && work[wi][4] == "regexp") {
        //  regexp = true;
       // }
        //if (what != "hashuid+PROJECTNAME")
        //  continue; // we can only do this inside a sequence, would be good if we can do more inside sequences!!!!
        int a = strtol(tag1.c_str(), NULL, 16);
        int b = strtol(tag2.c_str(), NULL, 16);
        if (tt.GetGroup() != a || tt.GetElement() != b) { // only anonymize the current item (its not a sequence)
          continue;
        }
        //fprintf(stdout, "  applyWork with %x %x %s %s %d\n", a, b, which.c_str(), what.c_str(), wi);
        bool somethingDone = applyWork(anon, ds, wi, params, trueStudyInstanceUID, filename, filenamestring, seriesdirname);
        if (debug_level > 2 && somethingDone) {
          fprintf(stdout, "%s   did something on tag %04x,%04x\n", spaces.c_str(), tt.GetGroup(), tt.GetElement());
        }
        fflush(stdout);
      }	*/
    }
  }
  return true;
}


/*std::string getStringValue(gdcm::Tag t, gdcm::StringFilter *sf) {
  // try a StringFilter if we have the right value representation
  gdcm::VR vr = DataSetHelper::ComputeVR(sf->GetFile(), ds, t);

  std::unordered_set<std::string> valids = { "AT", "FL", "FD", "OF", "SL", "SS", "UL", "US", "UT" };
  if (auto iter = valids.find(vr); iter != valids.end())
    return sf->ToString(t);
}*/

void *ReadFilesThread(void *voidparams) {
  threadparams *params = static_cast<threadparams *>(voidparams);
  gdcm::Global gl;
  
  const size_t nfiles = params->nfiles;
  for (unsigned int file = 0; file < nfiles; ++file) {
    const char *filename = params->filenames[file];
    // std::cerr << filename << std::endl;

    // gdcm::ImageReader reader;
    gdcm::Reader reader;
    reader.SetFileName(filename);
    try {
      if (!reader.Read()) {
        std::cerr << "Failed to read as DICOM: \"" << filename << "\" in thread " << params->thread << std::endl;
        continue; // try the next file
      }
    } catch (...) {
      std::cerr << "Failed to read: \"" << filename << "\" in thread " << params->thread << std::endl;
      continue;
    }
    // fprintf(stdout, "start processing: %s\n", filename);
    // process sequences as well
    // lets check if we can change the sequence that contains the ReferencedSOPInstanceUID inside the 0008,1115 sequence

    gdcm::DataSet &dss = reader.GetFile().GetDataSet();
    // some tags we need to get from the root element, otherwise we will have the case that
    // we get a StudyInstanceUID inside the 0008,1200 region which is only the referenced UID
    std::string trueStudyInstanceUID = "";
    typedef std::set<gdcm::DataElement> DataElementSet;
    typedef DataElementSet::const_iterator ConstIterator;
    ConstIterator cit = dss.GetDES().begin();
    for( ; cit != dss.GetDES().end(); ++cit) {
      std::stringstream strm;
      if (cit->GetTag() == gdcm::Tag(0x0020, 0x000d)) {
        const gdcm::DataElement &de = (*cit);
        (*cit).GetValue().Print(strm);
        trueStudyInstanceUID = strm.str();
        break;
      }
    }
    // can we get the modality from the file? We would like to use it as a prefix to the individual DICOM files filename
    /*std::string modalitystring = "";
    cit = dss.GetDES().begin();
    for( ; cit != dss.GetDES().end(); ++cit) {
      std::stringstream strm;
      if (cit->GetTag() == gdcm::Tag(0x0008, 0x0060)) {
        const gdcm::DataElement &de = (*cit);
        (*cit).GetValue().Print(strm);
        modalitystring = strm.str();
        modalitystring.erase(modalitystring.find_last_not_of(" \n\r\t")+1);
        // trim(modalitystring);
        break;
      }
      }*/

    gdcm::Anonymizer anon;
    gdcm::File &fileToAnon = reader.GetFile();
    anon.SetFile(fileToAnon);

    gdcm::MediaStorage ms;
    ms.SetFromFile(fileToAnon);
    // this next fails if we are looking at
    // Breast Tomosynthesis Image Storage   1.2.840.10008.5.1.4.1.1.13.1.3    Breast Tomosynthesis Image IOD
    /*if (!gdcm::Defs::GetIODNameFromMediaStorage(ms)) {
      std::cerr << "The Media Storage Type of your file is not supported: " << ms << std::endl;
      std::cerr << "Please report" << std::endl;
      continue;
      }*/
    gdcm::DataSet &ds = fileToAnon.GetDataSet();

    gdcm::StringFilter sf;
    sf.SetFile(fileToAnon);

    std::string modalitystring = "";
    if (ds.FindDataElement(gdcm::Tag(0x0008, 0x0060))) {
      modalitystring = sf.ToString(gdcm::Tag(0x0008, 0x0060));
    }
    
    // const gdcm::Image &image = reader.GetImage();
    // if we have the image here we can anonymize now and write again

    //
    // we might have some tags that should always be present, can we create those please?
    //
    for (int i = 0; i < work.size(); i++) {
      std::string tag1(work[i][0]);
      std::string tag2(work[i][1]);
      std::string which(work[i][2]);
      if (work[i].size() <= 4 || work[i][5] != "createIfMissing") {
        continue;
      }
      // we have a new entry, could be createIfMissing
      // check if the key exists by asking for its value
      int a = strtol(tag1.c_str(), NULL, 16);
      int b = strtol(tag2.c_str(), NULL, 16);
      // fprintf(stderr, "Looking for %s, ", which.c_str());
      gdcm::Tag hTag(a,b);
      if (hTag.IsPrivate()) {
        hTag = gdcm::PrivateTag(a,b);
      }

      // if 'a' is a private tag we need to use gdcm::PrivateTag(a,b) here!
      if (hTag.IsPrivate()?!ds.FindDataElement(gdcm::PrivateTag(a,b)):!ds.FindDataElement(hTag)) {

        // if the inserted element is a sequence we need to do more
        // Example
        if (which == "DeIdentificationMethodCodeSequence") {
          // add a sequence instead of a simple tag
          // for a sequence we need a Data Element first
          // insert the DataElement into an item
          // create a SequenceOfItems and add item
          // add sequence to dataset
          // TODO: the RSNA entries are numerical codes such as 113107, see
          // https://www.rsna.org/-/media/Files/RSNA/Covid-19/RICORD/RSNA-Covid-19-Deidentification-Protocol.pdf

          // Create a data element
          gdcm::DataElement de(hTag);
          de.SetVR(gdcm::VR(gdcm::VR::VRType::SQ));

          gdcm::SmartPointer<gdcm::SequenceOfItems> sq = new gdcm::SequenceOfItems();
          sq->SetLengthToUndefined();

          // Create an item
          gdcm::Item it;
          it.SetVLToUndefined(); // Needed to not popup error message

          gdcm::DataElement de2(gdcm::Tag(0x0008, 0x0104));
          std::string aaa = "Software"; // CodeMeaning
          //size_t len = aaa.size();
          //char *buf = new char[len];
          //strncpy(buf, aaa.c_str(), len);
          de2.SetByteValue(aaa.c_str(), (uint32_t)aaa.size());
          de2.SetVR(gdcm::VR(gdcm::VR::VRType::LO));

          gdcm::DataElement de3(gdcm::Tag(0x0008, 0x0100));
          aaa = "github.com/mmiv-center/DICOMAnonymizer"; // CodeValue
          //len = aaa.size();
          //char *buf2 = new char[len];
          //strncpy(buf2, aaa.c_str(), len);
          de3.SetByteValue(aaa.c_str(), (uint32_t)aaa.size());
          de3.SetVR(gdcm::VR(gdcm::VR::VRType::SH));

          gdcm::DataSet &nds = it.GetNestedDataSet();
          nds.Insert(de2);
          nds.Insert(de3);

          sq->AddItem(it);
          de.SetValue(*sq);
          ds.Insert(de);
        } else {
          //  add the element, we want to have it in all files we produce
          gdcm::DataElement elem(hTag);
          // set the correct VR - if that is in the dictionary
          //gdcm::Global gl;
          // hope this works always... not sure here
          try {
            elem.SetVR(gl.GetDicts().GetDictEntry(hTag, (const char *)nullptr).GetVR());
          } catch (const std::exception &ex) {
            std::cout << "Caught exception \"" << ex.what() << "\"\n";
          }
          //size_t len = 0;
          //char *buf = new char[len];
          std::string empty("");
          elem.SetByteValue(empty.c_str(), (uint32_t)empty.size());
          ds.Insert(elem);
        }
      }
    }

    // use the following tags
    // https://wiki.cancerimagingarchive.net/display/Public/De-identification+Knowledge+Base

    /*    Tag    Name    Action */

    std::string filenamestring = "";
    std::string seriesdirname = ""; // only used if byseries is true
    //gdcm::Trace::SetDebug(true);
    //gdcm::Trace::SetWarning(true);
    //gdcm::Trace::SetError(true);
    bool worked = AnonymizeBasedOnWork(fileToAnon, ds, trueStudyInstanceUID, params, filenamestring, seriesdirname, 0);
    
    //
    // do some more work after anonymizing
    //
    
    // hash of the patient id
    if (params->patientid == "hashuid") {
      if (ds.FindDataElement(gdcm::Tag(0x0010, 0x0010))) {
        std::string val = sf.ToString(gdcm::Tag(0x0010, 0x0010));
        std::string hash = SHA256::digestString(val).toHex();
        anon.Replace(gdcm::Tag(0x0010, 0x0010), limitToMaxLength(gdcm::Tag(0x0010, 0x0010), hash, ds).c_str());
      }
    } else {
      if (ds.FindDataElement(gdcm::Tag(0x0010, 0x0010)))
        anon.Replace(gdcm::Tag(0x0010, 0x0010), limitToMaxLength(gdcm::Tag(0x0010, 0x0010), params->patientid, ds).c_str());
    }
    if (params->patientid == "hashuid") {
      if (ds.FindDataElement(gdcm::Tag(0x0010, 0x0020))) {
        std::string val = sf.ToString(gdcm::Tag(0x0010, 0x0020));
        std::string hash = SHA256::digestString(val).toHex();
        anon.Replace(gdcm::Tag(0x0010, 0x0020), limitToMaxLength(gdcm::Tag(0x0010, 0x0020), hash, ds).c_str());
      }
    } else {
      if (ds.FindDataElement(gdcm::Tag(0x0010, 0x0020)))
        anon.Replace(gdcm::Tag(0x0010, 0x0020), limitToMaxLength(gdcm::Tag(0x0010, 0x0020), params->patientid, ds).c_str());
    }

    // We store the computed StudyInstanceUID in the StudyID tag.
    // This is used by the default setup of Sectra to identify the study (together with the AccessionNumber field).

    //
    // ISSUE: the tag can be inside of 0008,1200 (StudiesContainingOtherReferencedInstances)
    //        In this case the reported StudyInstanceUID is not the correct UID but the first
    //        one found - might be inside 0008,1200. This generates a new StudyInstanceUID
    //        in the anonymized version of the data.
    //
    std::string anonStudyInstanceUID = sf.ToString(gdcm::Tag(0x0020, 0x000D));
    // StudyID is 16 characters long and should be hashed if it exists
    // std::string anonStudyID = sf.ToString(gdcm::Tag(0x0020, 0x0010));
    // anon.Replace(gdcm::Tag(0x0020, 0x0010), limitToMaxLength(gdcm::Tag(0x0020, 0x0010), anonStudyID, ds).c_str());

    //{
    //  fprintf(stdout, "True studyInstanceUID is: %s\n", trueStudyInstanceUID.c_str());
    //}

    
    // fprintf(stdout, "project name is: %s\n", params->projectname.c_str());
    // this is a private tag --- does not work yet - we can only remove
    if (ds.FindDataElement(gdcm::PrivateTag(0x0013, 0x1010)))
      anon.Remove(gdcm::PrivateTag(0x0013, 0x1010));

    if (ds.FindDataElement(gdcm::PrivateTag(0x0013, 0x1013)))
      anon.Remove(gdcm::PrivateTag(0x0013, 0x1013));

    if (ds.FindDataElement(gdcm::PrivateTag(0x0013, 0x1011)))
      anon.Remove(gdcm::PrivateTag(0x0013, 0x1011));
    
    if (ds.FindDataElement(gdcm::PrivateTag(0x0013, 0x1012)))
      anon.Remove(gdcm::PrivateTag(0x0013, 0x1012));

    // ok save the file again
    std::string imageInstanceUID = filenamestring;
    if (imageInstanceUID == "") {
      if (debug_level > 0)
        fprintf(stderr, "Warning: cannot read image instance uid from %s, create a new one.\n", filename);
      gdcm::UIDGenerator gen;
      imageInstanceUID = gen.Generate();
      filenamestring = imageInstanceUID;
    }
    if (modalitystring != "") {
      filenamestring = modalitystring + "." + filenamestring;
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

    if (debug_level > 0)
      fprintf(stdout, "[%d %.0f %%] write to file: %s\n", params->thread, (1.0f*file)/nfiles*100.0f, fn.c_str());
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

void ReadFiles(size_t nfiles, const char *filenames[], const char *outputdir, const char *patientid, int dateincrement, bool byseries, bool old_style_uid, 
               int numthreads, const char *projectname, const char *sitename, const char *eventname, const char *siteid, std::string storeMappingAsJSON) {
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
  if (numthreads == 0) {
    numthreads = 1;
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
    params[thread].eventname = eventname;
    params[thread].nfiles = partition;
    params[thread].dateincrement = dateincrement;
    params[thread].byseries = byseries;
    params[thread].thread = thread;
    params[thread].projectname = projectname;
    params[thread].sitename = sitename;
    params[thread].siteid = siteid;
    params[thread].old_style_uid = old_style_uid;
    // params[thread].byThreadStudyInstanceUID
    // params[thread].byThreadSeriesInstanceUID
    if (thread == nthreads - 1) {
      // There is slightly more files to process in this thread:
      params[thread].nfiles += nfiles % nthreads;
    }
    assert(thread * partition < nfiles);
    int res = pthread_create(&pthread[thread], NULL, ReadFilesThread, &params[thread]);
    if (res) {
      if (debug_level > 0)
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
      for (std::map<std::string, std::string>::iterator it = params[thread].byThreadStudyInstanceUID.begin();
           it != params[thread].byThreadStudyInstanceUID.end(); ++it) {
        std::string key = it->first;
        //key.erase(key.find_last_not_of(" \n\r\t")+1);
        std::string value = it->second;
        //value.erase(key.find_last_not_of(" \n\r\t")+1);
        if (key.length() > 1 && key[key.length()-1] == '\0') {
          std::string::iterator it = key.end() -1;
          key.erase(it);
        }
        if (value.length() > 1 && value[value.length()-1] == '\0') {
          std::string::iterator it = value.end() -1;
          value.erase(it);
        }	
        uidmappings1.insert(std::pair<std::string, std::string>(key, value));
      }
    }
    for (unsigned int thread = 0; thread < nthreads; thread++) {
      for (std::map<std::string, std::string>::iterator it = params[thread].byThreadSeriesInstanceUID.begin();
           it != params[thread].byThreadSeriesInstanceUID.end(); ++it) {
        std::string key = it->first;
        //key.erase(key.find_last_not_of(" \n\r\t")+1);
        std::string value = it->second;
        //value.erase(key.find_last_not_of(" \n\r\t")+1);
        if (key.length() > 1 && key[key.length()-1] == '\0') {
          std::string::iterator it = key.end() -1;
          key.erase(it);
        }
        if (value.length() > 1 && value[value.length()-1] == '\0') {
          std::string::iterator it = value.end() -1;
          value.erase(it);
        }
        uidmappings2.insert(std::pair<std::string, std::string>(key, value));
      }
    }
    nlohmann::json ar;
    ar["StudyInstanceUID"] = {};
    ar["SeriesInstanceUID"] = {};
    for (std::map<std::string, std::string>::iterator it = uidmappings1.begin(); it != uidmappings1.end(); ++it) {
      ar["StudyInstanceUID"][it->first] = it->second;
    }
    for (std::map<std::string, std::string>::iterator it = uidmappings2.begin(); it != uidmappings2.end(); ++it) {
      ar["SeriesInstanceUID"][it->first] = it->second;
    }

    std::ofstream jsonfile(storeMappingAsJSON);
    if (!jsonfile.is_open()) {
      if (debug_level > 0)
        fprintf(stderr, "Failed to open file \"%s\"", storeMappingAsJSON.c_str());
    } else {
      jsonfile << ar;
      jsonfile.flush();
      jsonfile.close();
    }
  }

  delete[] pthread;
}

struct Arg : public option::Arg {
  static option::ArgStatus Required(const option::Option &option, bool) { return option.arg == 0 ? option::ARG_ILLEGAL : option::ARG_OK; }
  static option::ArgStatus Empty(const option::Option &option, bool) { return (option.arg == 0 || option.arg[0] == 0) ? option::ARG_OK : option::ARG_IGNORE; }
};

enum optionIndex {
  UNKNOWN,
  INPUT,
  OUTPUT,
  PATIENTID,
  EVENTNAME,
  PROJECTNAME,
  SITENAME,
  DATEINCREMENT,
  EXPORTANON,
  BYSERIES,
  NUMTHREADS,
  TAGCHANGE,
  STOREMAPPING,
  SITEID,
  REGTAGCHANGE,
  OLDSTYLEUID,
  VERBOSE,
  VERSION
};
const option::Descriptor usage[] = {
    {UNKNOWN, 0, "", "", option::Arg::None,
     "Anonymize DICOM images. Read DICOM image series and write "
     "out an anonymized version of the files based on the recommendations of "
     "the cancer imaging archive.\n\n"
     "USAGE: anonymize [options]\n\n"
     "Options:"},
    {INPUT,         0, "i", "input", Arg::Required, "  --input, -i  \tInput directory."},
    {OUTPUT,        0, "o", "output", Arg::Required, "  --output, -o  \tOutput directory."},
    {PATIENTID,     0, "p", "patientid", Arg::Required, "  --patientid, -p  \tPatient ID after anonymization (default is \"hashuid\" to hash the existing id)."},
    {EVENTNAME,     0, "e", "eventname", Arg::Required, "  --eventname, -e  \tEvent name string (default is \"\")."},
    {PROJECTNAME,   0, "j", "projectname", Arg::Required, "  --projectname, -j  \tProject name. By default the project name is copied to the InstitutionName tag as well as tags in group 12."},
    {SITENAME, 0, "s", "sitename", Arg::Required, "  --sitename, -s  \tSiteName DICOM tag."},
    {SITEID,        0, "w", "siteid", Arg::Required, "  --siteid, -w  \tSiteID DICOM tag."},
    {DATEINCREMENT, 0, "d", "dateincrement", Arg::Required, "  --dateincrement, -d  \tNumber of days that should be added to dates."},
    {EXPORTANON,    0, "a", "exportanon", Arg::Required,
     "  --exportanon, -a  \tWrites the anonymization structure as a json file "
     "to disk and quits the program. There is no way to import a new file currently."},
    {BYSERIES,      0, "b", "byseries", Arg::None,
     "  --byseries, -b  \tFlag to writes each DICOM file into a separate directory "
     "by image series."},
    {OLDSTYLEUID,   0, "u", "oldstyleuid", Arg::None,
     "  --oldstyleuid, -u  \tFlag to allow alpha-numeric characters as UIDs (deprecated). Default is to only generate standard conformant UIDs with characters '0'-'9' and '.'."},
    {STOREMAPPING,  0, "m", "storemapping", Arg::None, "  --storemapping, -m  \tFlag to store the StudyInstanceUID mapping as a JSON file."},
    {TAGCHANGE,     0, "P", "tagchange", Arg::Required, "  --tagchange, -P  \tChanges the default behavior for a tag in the build-in rules."},
    {REGTAGCHANGE,  0, "R", "regtagchange", Arg::Required,
     "  --regtagchange, -R  \tChanges the default behavior for a tag in the build-in rules (understands regular expressions, retains all capturing groups)."},
    {NUMTHREADS,    0, "t", "numthreads", Arg::Required, "  --numthreads, -t  \tHow many threads should be used (default 4)."},
    {VERSION,       0, "v", "version", Arg::None, "  --version, -v  \tPrint version number."},
    {VERBOSE,       0, "l", "debug", Arg::None, "  --debug, -l  \tPrint debug messages. Can be used more than once."},
    {UNKNOWN,       0, "", "", Arg::None,
     "\nExamples:\n"
     "  anonymize --input directory --output directory --patientid bla -d 42 -b\n"
     "  anonymize --exportanon rules.json\n"
     "  anonymize --tagchange \"0008,0080=PROJECTNAME\" --tagchange \"0008,0081=bla\" \\"
     "            --exportanon rules.json\n"},
    {0, 0, 0, 0, 0, 0}};

// TODO: would be good to start anonymizing already while its still trying to find more files...
std::vector<std::string> listFiles(const std::string &path) {
  std::vector<std::string> files;
  using recursive_directory_iterator = std::filesystem::recursive_directory_iterator;
  for (const auto& dirEntry : recursive_directory_iterator(path)) {
    //std::cout << dirEntry << std::endl;
    if (fs::is_regular_file(dirEntry.path())) {
      files.push_back(dirEntry.path());
      if (files.size() % 100 == 0 && debug_level > 0) {
        fprintf(stdout, "\rreading files (%'lu) ...", files.size());
        fflush(stdout);
      }
    }
  }
  return files;
}

int main(int argc, char *argv[]) {

  setlocale(LC_NUMERIC, "");
  argc -= (argc > 0);
  argv += (argc > 0); // skip program name argv[0] if present

  option::Stats stats(usage, argc, argv);
  std::vector<option::Option> options(stats.options_max);
  std::vector<option::Option> buffer(stats.buffer_max);
  option::Parser parse(usage, argc, argv, &options[0], &buffer[0]);

  if (parse.error())
    return 1;

  if (argc == 0) {
    option::printUsage(std::cout, usage);
    return 0;
  }

  if (options[VERSION]) {
    fprintf(stdout, "anonymizer version 1.1.0.%s\n", VERSION_DATE);
    return 0;
  }

  for (option::Option *opt = options[UNKNOWN]; opt; opt = opt->next())
    std::cout << "Unknown option: " << std::string(opt->name, opt->namelen) << "\n";

  std::string input;
  std::string output;
  std::string patientID = ""; // if no patient id is provided in the command line use and empty string
  std::string sitename = " ";
  std::string siteid = "";
  std::string eventname = "";
  int dateincrement = 42;
  std::string exportanonfilename = ""; // anon.json
  bool byseries = false;
  bool old_style_uid = false; // default is that we do not use old style alphanumeric characters in uid
  int numthreads = 4;
  std::string projectname = "";
  std::string storeMappingAsJSON = "";
  for (int i = 0; i < parse.optionsCount(); ++i) {
    option::Option &opt = buffer[i];
    // fprintf(stdout, "Argument #%d is ", i);
    switch (opt.index()) {
      case INPUT:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--input '%s'\n", opt.arg);
          input = opt.arg;
        } else {
          fprintf(stderr, "Error: --input needs a directory specified\n");
          exit(-1);
        }
        break;
      case OUTPUT:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--output '%s'\n", opt.arg);
          output = opt.arg;
        } else {
          fprintf(stderr, "Error: --output needs a directory specified\n");
          exit(-1);
        }
        // check output directory, exists and is_dir, if not exist create
        if (!gdcm::System::FileExists(output.c_str())) {
          // create the directory
          mkdir(output.c_str(), 0777);
          if (gdcm::System::FileIsDirectory(output.c_str())) {
            if (debug_level > 0)
              fprintf(stdout, "--output created directory \"%s\"\n", output.c_str());
          } else {
            fprintf(stderr, "Error: could not create directory \"%s\"\n", output.c_str());
            exit(-1);
          }
        }
        if (!gdcm::System::FileIsDirectory(output.c_str())) {
          fprintf(stdout, "--output should be a directory, not a file\n");
          exit(-1);
        }
        break;
      case PATIENTID:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--patientid '%s'\n", opt.arg);
          patientID = opt.arg;
        } else {
          fprintf(stderr, "Error: --patientid needs a string specified\n");
          exit(-1);
        }
        break;
      case PROJECTNAME:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--projectname '%s'\n", opt.arg);
          projectname = opt.arg;
        } else {
          fprintf(stderr, "Error: --projectname needs a string specified\n");
          exit(-1);
        }
        break;
      case SITENAME:
        if (opt.arg) {
          if (debug_level > 0)
	    fprintf(stdout, "--sitename '%s'\n", opt.arg);
          sitename = opt.arg;
        } else {
          fprintf(stderr, "Error: --sitename needs a string specified\n");
          exit(-1);
        }
        break;
      case EVENTNAME:
        if (opt.arg) {
          if (debug_level > 0)
	    fprintf(stdout, "--eventname '%s'\n", opt.arg);
          eventname = opt.arg;
        } else {
          fprintf(stderr, "Error: --eventname needs a string specified\n");
          exit(-1);
        }
        break;
      case SITEID:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--siteid '%s'\n", opt.arg);
          siteid = opt.arg;
        } else {
          fprintf(stderr, "Error: --siteid needs a string specified\n");
          exit(-1);
        }
        break;
      case DATEINCREMENT:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--dateincrement %d\n", atoi(opt.arg));
          dateincrement = atoi(opt.arg);
        } else {
          fprintf(stderr, "Error: --dateincrement needs an integer specified\n");
          exit(-1);
        }
        break;
      case BYSERIES:
        if (debug_level > 0)
          fprintf(stdout, "--byseries\n");
        byseries = true;
        break;
      case OLDSTYLEUID:
        if (debug_level > 0)
          fprintf(stdout, "--oldstyleuid\n");
        old_style_uid = true;
        break;
      case VERBOSE:
        if (debug_level > 0)
          fprintf(stdout, "--debug\n");
        debug_level++;
        break;
      case STOREMAPPING:
        if (debug_level > 0)
          fprintf(stdout, "--storemapping\n");
        storeMappingAsJSON = "mapping.json";
        break;
      case TAGCHANGE:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--tagchange %s\n", opt.arg);
          std::string tagchange = opt.arg;
          // apply this tag to the rules, should overwrite what was in there, or add another rule
          std::string tag1;
          std::string tag2;
          std::string res;
          int posEqn = tagchange.find("=");
          if (posEqn == std::string::npos) {
            fprintf(stderr, "Error: --tagchange error, string does not match pattern %%o,%%o=%%s\n");
            exit(-1);
          }
          res = tagchange.substr(posEqn + 1, std::string::npos); // until the end of the string
          std::string front = tagchange.substr(0, posEqn);
          int posComma = front.find(",");
          if (posComma == std::string::npos) {
            fprintf(stderr, "Error: --tagchange error, string does not match pattern %%o,%%o=%%s\n");
            exit(-1);
          }
          tag1 = front.substr(0, posComma);
          tag2 = front.substr(posComma + 1, std::string::npos);
          // fprintf(stdout, "got a tagchange of %s,%s = %s\n", tag1.c_str(), tag2.c_str(), res.c_str());
          int a = strtol(tag1.c_str(), NULL, 16);
          int b = strtol(tag2.c_str(), NULL, 16); // did this work? we should check here and not just add
          // now check in work if we add or replace this rule
          bool found = false;
          for (int j = 0; j < work.size(); j++) {
            // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
            std::string ttag1(work[j][0]);
            std::string ttag2(work[j][1]);
            std::string twhich(work[j][2]);
            if (tag1 == ttag1 && tag2 == ttag2) {
              // found and overwrite
              found = true;
              work[j][3] = res; // overwrite the value, [2] is name
              work[j][4] = std::string("");
              work[j][5] = std::string("createIfMissing");
            }
          }
          if (!found) {
            // append as a new rule
            nlohmann::json ar;
            ar.push_back(tag1);
            ar.push_back(tag2);
            ar.push_back(res);
            ar.push_back(res);
	          ar.push_back(std::string(""));
	          ar.push_back(std::string("1"));
            work.push_back(ar);
          }
        } else {
          fprintf(stderr, "Error: --tagchange needs a string specification like this \"0080,0010=ANON\"\n");
          exit(-1);
        }
        break;
      case REGTAGCHANGE:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--regtagchange %s\n", opt.arg);
          std::string tagchange = opt.arg;
          // apply this tag to the rules, should overwrite what was in there, or add another rule
          std::string tag1;
          std::string tag2;
          std::string res;
          int posEqn = tagchange.find("=");
          if (posEqn == std::string::npos) {
            fprintf(stderr, "Error: --regtagchange error, string does not match pattern %%o,%%o=%%s\n");
            exit(-1);
          }
          res = tagchange.substr(posEqn + 1, std::string::npos); // until the end of the string
          std::string front = tagchange.substr(0, posEqn);
          int posComma = front.find(",");
          if (posComma == std::string::npos) {
            fprintf(stderr, "Error: --regtagchange error, string does not match pattern %%o,%%o=%%s\n");
            exit(-1);
          }
          tag1 = front.substr(0, posComma);
          tag2 = front.substr(posComma + 1, std::string::npos);
          if (debug_level > 0)
            fprintf(stdout, "got a regtagchange of %s,%s = %s\n", tag1.c_str(), tag2.c_str(), res.c_str());
          int a = strtol(tag1.c_str(), NULL, 16);
          int b = strtol(tag2.c_str(), NULL, 16); // did this work? we should check here and not just add
          // now check in work if we add or replace this rule
          bool found = false;
          for (int j = 0; j < work.size(); j++) {
            // fprintf(stdout, "convert tag: %d/%lu\n", i, work.size());
            std::string ttag1(work[j][0]);
            std::string ttag2(work[j][1]);
            std::string twhich(work[j][2]);
            if (tag1 == ttag1 && tag2 == ttag2) {
              // found and overwrite
              found = true;
              work[j][3] = res;      // overwrite the value, [2] is name
              work[j][4] = "regexp"; // mark this as a regular expression tag change
              work[j][5] = "createIfMissing"; // mark as imported from command line - needs to be written even if missing
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
	          ar.push_back(std::string("1"));
            work.push_back(ar);
          }
        } else {
          fprintf(stderr, "Error: --regtagchange needs a string specification like this \"0080,0010=\\[(.*) [0-9]+\\]\"\n");
          exit(-1);
        }
        break;
      case NUMTHREADS:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--numthreads %d\n", atoi(opt.arg));
          numthreads = atoi(opt.arg);
        } else {
          fprintf(stderr, "Error: --numthreads needs an integer specified\n");
          exit(-1);
        }
        break;
      case EXPORTANON:
        if (opt.arg) {
          if (debug_level > 0)
            fprintf(stdout, "--exportanon %s\n", opt.arg);
          exportanonfilename = opt.arg;

          // if we need to export the json file, do that and quit
          if (exportanonfilename.length() > 0) {
            fs::path export_anon_filename = exportanonfilename;
            if (debug_level > 0)
              fprintf(stdout,
                      "Write the anonymization tag information as a file to disk "
                      "and exit (\"%s\").\n",
                      exportanonfilename.c_str());
            if (export_anon_filename.extension() == ".csv") {
              std::ofstream csvfile(exportanonfilename);
              if (!csvfile.is_open()) {
                fprintf(stderr, "Failed to open file \"%s\"\n", exportanonfilename.c_str());
              } else {
                int max_length = 0;
                for (int j = 0; j < work.size(); j++) {
                  if (max_length < work[j].size())
                    max_length = work[j].size();
                }
                for (int k = 0; k < work.size(); k++) {
                  for (int j = 0; j < max_length - 1; j++) {
                    if (work[k].size() > j) {
                      csvfile << work[k][j];
                    }
                    if (j < max_length - 2) {
                      csvfile << ",";
                    }
                  }
                  csvfile << "\n";
                }
                csvfile.flush();
              }
            } else {
              std::ofstream jsonfile(exportanonfilename);
              if (!jsonfile.is_open()) {
                fprintf(stderr, "Failed to open file \"%s\"\n", exportanonfilename.c_str());
              } else {
                jsonfile << work;
                jsonfile.flush();
              }
            }
            exit(0);
          }
        } else {
          fprintf(stderr, "Error: --exportanon needs a filename\n");
          exit(-1);
        }
        break;
      case UNKNOWN:
        // not possible because Arg::Unknown returns ARG_ILLEGAL
        // which aborts the parse with an error
        break;
    }
  }
  // based on the debug_level we can disable the warnings and error messages from gdcm
  if (debug_level > 1) {
     gdcm::Trace::DebugOn();
     gdcm::Trace::ErrorOn();
  } else {
     gdcm::Trace::DebugOff();
     gdcm::Trace::ErrorOff();
  }

  // number of processed files
  size_t nfiles = 0;

  // Check if user pass in a single directory
  if (gdcm::System::FileIsDirectory(input.c_str())) {
    std::vector<std::string> files = listFiles(input.c_str());

    nfiles = files.size();
    const char **filenames = new const char *[nfiles];
    for (unsigned int i = 0; i < nfiles; ++i) {
      filenames[i] = files[i].c_str();
    }
    if (storeMappingAsJSON.length() > 0) {
      storeMappingAsJSON = output + std::string("/") + storeMappingAsJSON;
    }
    if (nfiles == 0) {
      fprintf(stderr, "No files found.\n");
      fflush(stderr);
      exit(-1);
    }

    // before we try to anonymize our files we should create a cache of work,
    // We need to know if a tag is going to be anonymized (based on group element) and where
    // in work the corresponding entry can be found.
    createWorkCache();

    // ReadFiles(nfiles, filenames, output.c_str(), numthreads, confidence, storeMappingAsJSON);
    ReadFiles(nfiles, filenames, output.c_str(), patientID.c_str(), dateincrement, byseries, old_style_uid, numthreads, projectname.c_str(), sitename.c_str(),
              eventname.c_str(), siteid.c_str(), storeMappingAsJSON);
    delete[] filenames;
  } else {
    // its a single file, process that
    // but is it a single file???? Could be a directory that not exists
    if (!gdcm::System::FileExists(input.c_str())) {
      fprintf(stderr, "File or directory does not exist (%s).\n", input.c_str());
      fflush(stderr);
      exit(-1);
    }

    const char **filenames = new const char *[1];
    filenames[0] = input.c_str();
    nfiles = 1;
    // ReadFiles(1, filenames, output.c_str(), 1, confidence, storeMappingAsJSON);
    ReadFiles(nfiles, filenames, output.c_str(), patientID.c_str(), dateincrement, byseries, old_style_uid, numthreads, projectname.c_str(), sitename.c_str(), eventname.c_str(),
              siteid.c_str(), storeMappingAsJSON);
  }
  if (debug_level > 0)
    fprintf(stdout, "Done [%'zu file%s processed].\n", nfiles, nfiles==1?"":"s");

  return 0;
}

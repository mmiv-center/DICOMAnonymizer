#ifndef INCLUDE_DATEPROCESSING_HPP_
#define INCLUDE_DATEPROCESSING_HPP_

#include <sys/time.h>

struct sdate {
  long y;
  long m;
  long d;
  };

struct sdate date1;
struct sdate date2;
struct sdate dtest;
struct timeval now, *pnow;
struct tm today, *ptoday;
long offset, g1, g2;
long calstart;   /* Earliest date on Gregorian calendar */
long args[6];
long *i, j;
char *progname;
const char warn1[] = "WARNING: Dates before Oct. 1582 are inaccurate.";

long gday(struct sdate d) {       /* convert date to day number */
  long  y, m;

  m = (d.m + 9)%12;                /* mar=0, feb=11 */
  y = d.y - m/10;                     /* if Jan/Feb, year-- */
  return y*365 + y/4 - y/100 + y/400 + (m*306 + 5)/10 + (d.d - 1);
  }

struct sdate dtf(long d) { /* convert day number to y,m,d format */
  struct sdate pd;
  long y, ddd, mm, dd, mi;

  y = (10000*d + 14780)/3652425;
  ddd = d - (y*365 + y/4 - y/100 + y/400);
  if (ddd < 0) {
    y--;
    ddd = d - (y*365 + y/4 - y/100 + y/400);
    }
  mi = (52 + 100*ddd)/3060;
  pd.y = y + (mi + 2)/12;
  pd.m = (mi + 2)%12 + 1;
  pd.d = ddd - (mi*306 + 5)/10 + 1;
  return pd;
  }

long legald(struct sdate d) {   /* return gday, or exit if bad date */
  struct sdate t;
  long g;

  g = gday(d);
  if (g < calstart) fprintf(stderr,"%s: %s\n", progname, warn1);
  t = dtf(g);
  if (d.y == t.y && d.m == t.m && d.d == t.d) {
    return g;
    }
  else {
    fprintf(stderr,"%s: Illegal date %ld %ld %ld.\n",
            progname, d.y, d.m, d.d);
    exit(2);
    }
  }
#endif /* OPTIONPARSER_H_ */

/* 
    FIIN - Universal firmware decompressor
    Copyright (C) 2001,2002 Jacek Lipkowski <sq5bpf@andra.com.pl>

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

TODO: 
- add more decompressors if needed
- add even more pointless switches to make it seem to have more features
- try it on more firmware (let me know if you do :)

Changelog:
version 0.2
- made do_gzip, do_pkzip, do_lha etc into one generic function
- used getopt()

*/


#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>

#define VER "0.2"

/* signatures taken from /etc/magic */
char gzip_sig[3] = "\x1f\x8b\x08";
char pkzip_sig[4] = "PK\x03\x04";
char compress_sig[2] = "\x1f\x9d";
char bzip2_sig[3] = "BZh";
char arj_sig[2] = "\xea\x60";
//char pack_sig[2] = "\x1f\x1e";

#define LHA_OFFSET 2
char lh0_sig[5] = "-lh0-";	//offset=2;
char lh1_sig[5] = "-lh1-";	//offset=2;
char lz4_sig[5] = "-lz4-";	//offset=2;
char lzs_sig[5] = "-lzs-";	//offset=2;
char lh_sig[5] = "-lh\x20-";	//offset=2;
char lhd_sig[5] = "-lhd-";	//offset=2;
char lh2_sig[5] = "-lh2-";	//offset=2;
char lh3_sig[5] = "-lh3-";	//offset=2;
char lh4_sig[5] = "-lh4-";	//offset=2;
char lh5_sig[5] = "-lh5-";	//offset=2;

#define BSIZE 8192

int have_gzip = 1;
int have_unzip = 1;
int have_lha = 1;
int have_bzip2 = 1;
int have_unarj = 1;

int verbose = 0;
int allways_unlink = 0;

char *infile = NULL;
char *outbase = NULL;

/* The system(3) from linux glibc 2.x returns the exit status of the command
in the high byte contrary to what the manpage says. It _is_ documented
in the IRIX manpages. */

/* setting this shifts the return value of system(3) 8 bits right */
#define SHIFT_SYSTEM
int try = 0;
unsigned long offset = 0;


void
banner ()
{
  printf
    ("FIIN v%s, Copyright (C) 2001 Jacek Lipkowski <sq5bpf@andra.com.pl>\n",
     VER);
  printf ("FIIN comes with ABSOLUTELY NO WARRANTY\n");
  printf ("This is free software, and you are welcome to redistribute it\n");
  printf
    ("under the GPL version 2 license. Please see the file LICENSE for details.\n\n");
}

void
helpme ()
{

  printf ("Usage:\tfiin <options>\n");
  printf ("options:\n-u always unlink (don't create files)\n");
  printf ("-v verbose (use twice for more junk on the screen)\n-h help\n");
  printf ("-w method - without method (gzip, unzip, bzip2, lha, unarj)\n");
  printf
    ("-f input file\n-o outfile basename (equals input file if not specified)\n\n");
  printf ("example:\n");
  printf
    ("fiin -f firmware.img -o decompressed_firmware -v -v -w unarj -w bzip2\n\n");
  exit (1);
}


char buf[16];
FILE *f;
int
wbuf (char c)
{
  int i;
  for (i = 0; i < (sizeof (buf) - 1); i++)
    buf[i] = buf[i + 1];
  buf[sizeof (buf) - 1] = c;
  return (1);
}



int
check_sig (int size, char *sig)
{
  if (memcmp (&buf[sizeof (buf) - size], sig, size) == 0)
    return (1);
  return (0);
}


/* do_generic: generic checker (replaces do_gzip, do_compress etc) */

/* variables:
nam - part of the name of our archive
method - decompession method (eg. gzip)
suffix - file extension (eg. .gz)
sig_len - signature length
check_cmd - command to check
decompress_cmd - command to decompress
sig_offs - offset of signature
have_method - flag that tells if the metod is avaliable
ok1,ok2 - valid return values
*/

int
do_generic (char *nam, char *method, char *suffix, int sig_len,
	    char *check_cmd, char *decompress_cmd, int sig_offs,
	    int *have_method, int ok1, int ok2)
{
  char outname[80];
  char cmdbuf[128];
  FILE *g;
  char *tbuf;
  int re;
  tbuf = malloc (BSIZE);
  if (!tbuf)
    {
      perror ("malloc");
      exit (1);
    }

  sprintf ((char *) &outname, "%s-%i%s", nam, try, suffix);
  g = fopen ((char *) &outname, "w");
  fwrite (&buf[sizeof (buf) - sig_len - sig_offs], 1, sig_len + sig_offs, g);
  while (!feof (f))
    {
      re = fread (tbuf, 1, BSIZE, f);
      if (fwrite (tbuf, 1, re, g) != re)
	{
	  perror ("fwrite");
	  exit (1);
	}
    }
  fclose (g);
  sprintf ((char *) &cmdbuf, check_cmd, outname);
  if (verbose < 2)
    strcat ((char *) &cmdbuf, " >/dev/null 2>/dev/null");
  re = system ((char *) &cmdbuf);
#ifdef SHIFT_SYSTEM
  re = re >> 8;
#endif
  if (re == 127)
    {
      fprintf (stderr, "You don't appear to have %s installed\n", method);
      if (have_method)
	*have_method = 0;
    }



  if ((re == ok1) || (re == ok2))
    {
      if (!verbose)
	printf ("\n*** image at offset %p saved as %s ***\n", offset,
		outname);
      if (allways_unlink)
	unlink ((char *) &outname);
      try++;
      return (1);
    }
  else
    {
      if (verbose)
	printf ("\n*** image %s didn't verify, deleting ***\n", outname);
      unlink ((char *) &outname);
    }

  return (0);
}				/* do_generic */

/* your standard getopt parser */
int
parse_cmdline (int argc, char **argv)
{
  int opt;
/* options:
-u always unlink (don't create files)
-v verbose
-h help
-w method - without method
-f input file
-o out file basename
*/
  while ((opt = getopt (argc, argv, "uvhw:f:o:")) != EOF)
    {
      switch (opt)
	{
	case 'h':
	  helpme ();
	  exit (0);
	  break;
	case 'v':
	  verbose++;
	  break;
	case 'u':
	  allways_unlink = 1;
	  break;
	case 'f':
	  infile = optarg;
	  break;
	case 'o':
	  outbase = optarg;
	  break;
	case 'w':
	  if (strcmp (optarg, "bzip2") == 0)
	    have_bzip2 = 0;
	  if (strcmp (optarg, "gzip") == 0)
	    have_gzip = 0;
	  if (strcmp (optarg, "unzip") == 0)
	    have_unzip = 0;
	  if (strcmp (optarg, "unarj") == 0)
	    have_unarj = 0;
	  if (strcmp (optarg, "lha") == 0)
	    have_lha = 0;
	  break;
	default:
	  fprintf (stderr, "Unknown command line option %s\n", *argv);
	  helpme ();
	  exit (1);
	}
      /*switch */

    }				/* while */
  if (optind != argc)
    {
      fprintf (stderr, "Too many parameters");
      helpme ();
      exit (1);
    }



}

int
main (int argc, char **argv)
{
  char c;
  banner ();
  parse_cmdline (argc, argv);
  if (!infile)
    {
      printf ("\nPlease specify an input filename with the -f option\n\n");
      helpme ();
      exit (1);
    }
  if (!outbase)
    outbase = infile;
  bzero ((char *) &buf, sizeof (buf));
  f = fopen (infile, "r");
  if (!f)
    {
      perror ("fopen");
      exit (1);
    }

  while (!feof (f))
    {
      if (fread (&c, 1, 1, f) != 1)
	break;
      wbuf (c);
/*gzip?*/
      if (have_gzip && (check_sig (sizeof (gzip_sig), (char *) &gzip_sig)))
	{
	  offset = ftell (f);
	  if (verbose)
	    printf
	      ("\n*** Found possible gzip-compressed image at 0x%8.8x ***\n",
	       offset - sizeof (gzip_sig));
	  do_generic ((char *) outbase, "gzip", ".gz", sizeof (gzip_sig),
		      "gunzip -v -t %s", NULL, 0, (int *) &have_gzip, 0, 2);
	  fseek (f, offset, SEEK_SET);
	}			//if gzip

/*zip?*/
      if (have_unzip && (check_sig (sizeof (pkzip_sig), (char *) &pkzip_sig)))
	{
	  offset = ftell (f);
	  if (verbose)
	    printf
	      ("\n*** Found possible zip-compressed image at 0x%8.8x ***\n",
	       offset - sizeof (pkzip_sig));
	  do_generic ((char *) outbase, "zip", ".zip", sizeof (pkzip_sig),
		      "unzip -v -l %s", NULL, 0, (int *) &have_unzip, 0, 2);
	  fseek (f, offset, SEEK_SET);
	}			//if zip

/*compress*/
      if (have_gzip
	  && (check_sig (sizeof (compress_sig), (char *) &compress_sig)))
	{
	  offset = ftell (f);
	  if (verbose)
	    printf ("\n*** Found possible compress-ed image at 0x%8.8x ***\n",
		    offset - sizeof (compress_sig));
	  do_generic ((char *) outbase, "compress", ".Z",
		      sizeof (compress_sig), "gunzip -v -t %s", NULL, 0,
		      (int *) &have_gzip, 0, 2);
	  fseek (f, offset, SEEK_SET);
	}			//if compress

/*bzip2*/
      if (have_bzip2 && (check_sig (sizeof (bzip2_sig), (char *) &bzip2_sig)))
	{
	  offset = ftell (f);
	  if (verbose)
	    printf ("\n*** Found possible bzip2-ed image at 0x%8.8x ***\n",
		    offset - sizeof (compress_sig));
	  do_generic ((char *) outbase, "bzip2", ".bz2", sizeof (bzip2_sig),
		      "bzip2 -vv -t %s", NULL, 0, (int *) &have_bzip2, 0, 0);
	  fseek (f, offset, SEEK_SET);
	}			//if bzip2

/*unarj*/
      if (have_unarj && (check_sig (sizeof (arj_sig), (char *) &arj_sig)))
	{
	  offset = ftell (f);
	  if (verbose)
	    printf
	      ("\n*** Found possible arj compressed image at 0x%8.8x ***\n",
	       offset - sizeof (arj_sig));
	  do_generic ((char *) outbase, "unarj", ".arj", sizeof (arj_sig),
		      "arj t %s", NULL, 0, (int *) &have_unarj, 0, 0);
	  fseek (f, offset, SEEK_SET);
	}			//if arj

/*lha/lharc*/
      if (have_lha && (check_sig (sizeof (lh0_sig), (char *) &lh0_sig) ||
		       check_sig (sizeof (lh1_sig), (char *) &lh1_sig) ||
		       check_sig (sizeof (lz4_sig), (char *) &lz4_sig) ||
		       check_sig (sizeof (lzs_sig), (char *) &lzs_sig) ||
		       check_sig (sizeof (lh_sig), (char *) &lh_sig) ||
		       check_sig (sizeof (lhd_sig), (char *) &lhd_sig) ||
		       check_sig (sizeof (lh2_sig), (char *) &lh2_sig) ||
		       check_sig (sizeof (lh3_sig), (char *) &lh3_sig) ||
		       check_sig (sizeof (lh4_sig), (char *) &lh4_sig) ||
		       check_sig (sizeof (lh5_sig), (char *) &lh5_sig)))
	{
	  offset = ftell (f);
	  if (verbose)
	    printf
	      ("\n*** Found possible lha-compressed image at 0x%8.8x ***\n",
	       offset - sizeof (lh5_sig) - LHA_OFFSET);
	  do_generic ((char *) outbase, "lha", ".lha", sizeof (lh5_sig),
		      "lha v %s", NULL, LHA_OFFSET, (int *) &have_lha, 0, 2);
	  fseek (f, offset, SEEK_SET);
	}			//if lha/lharc


    }				//while


  return (0);
}				//main

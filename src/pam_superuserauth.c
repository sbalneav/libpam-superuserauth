/*
 * pam_sshauth: PAM module for authentication via a remote ssh server.
 * Copyright (C) 2016 Scott Balneaves <sbalneav@ltsp.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <shadow.h>
#include <crypt.h>
#include <config.h>

/*
 * PAM_SM_* define.
 */

#define PAM_SM_AUTH		/* supports Authentication */

#include <security/pam_modules.h>

static int use_first_pass = 0;
static char *superuser = "root";

/*
 * check_password
 *
 * Check the collected password against the shadow password entry for the
 * superuser.
 */

static int
check_password (const void *password)
{
  struct spwd *sp;

  /*
   * Grab the shadow password entry for the superuser
   * If we cant't get it, return error.
   */

  if ((sp = getspnam (superuser)) == NULL)
    {
      return PAM_AUTH_ERR;
    }

  /*
   * If no password or empty password, return error.
   */

  if ((sp->sp_pwdp == NULL) || (strlen (sp->sp_pwdp) == 0))
    {
      return PAM_AUTH_ERR;
    }

  /*
   * Get the salt from the password.  Assumes the SHA type passwords currently
   * used in GNU/Linux. i.e. $1$xxxxx$yyyy or $6$xxxxx$yyyyy.
   */

  if (!strcmp (sp->sp_pwdp, crypt (password, sp->sp_pwdp)))
    {
      return PAM_SUCCESS;
    }

  return PAM_AUTH_ERR;
}

/*
 * pam_process_args
 *
 * Look for the "use_first_pass" and "superuser=xxxx" args.
 */

static void
pam_process_args (int argc, const char **argv)
{
  for (; argc-- > 0; ++argv)
    {
      if (!strcmp (*argv, "use_first_pass"))
	{
	  use_first_pass++;
	}

      if (!strncmp (*argv, "superuser", 9))
	{
	  superuser = (char *) (*argv + 10);
	}
    }
}

/*
 * PAM functions
 */

PAM_EXTERN int
pam_sm_authenticate (pam_handle_t * pamh, int flags, int argc,
		     const char **argv)
{
  const void *password;
  int pam_result;

  pam_process_args (argc, argv);

  /*
   * Get password
   */

  if (use_first_pass)
    {
      pam_result = pam_get_item (pamh, PAM_AUTHTOK, &password);
      if (pam_result != PAM_SUCCESS)
	{
	  pam_syslog (pamh, LOG_ERR,
		      "Couldn't obtain password from pam stack");
	  return pam_result;
	}
    }
  else
    {
      pam_result =
	pam_prompt (pamh, PAM_PROMPT_ECHO_OFF, &password, "Password:");
      if (pam_result != PAM_SUCCESS)
	{
	  pam_syslog (pamh, LOG_ERR,
		      "Couldn't obtain password from pam_prompt");
	  return pam_result;
	}
      pam_result = pam_set_item (pamh, PAM_AUTHTOK, password);
      if (pam_result != PAM_SUCCESS)
	{
	  pam_syslog (pamh, LOG_ERR, "Couldn't store PAM_AUTHTOK");
	  return pam_result;
	}
    }

  /*
   * authenticate
   */

  pam_result = check_password (password);
  if (pam_result == PAM_SUCCESS)
    {
      pam_syslog (pamh, LOG_INFO,
		  "Authenticated user with superuser password");
    }
  return pam_result;
}

PAM_EXTERN int
pam_sm_setcred (pam_handle_t * pamh, int flags, int argc, const char **argv)
{
  return PAM_SUCCESS;
}

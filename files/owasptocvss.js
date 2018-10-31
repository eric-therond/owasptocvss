// min bounty amount
var b_min = 50;
// max bounty amount
var b_max = 10000;
// internal parameter
var n = 1;
// max cvss
var Cvss_max = 10;


function computeBountyAmount(Cvss) {
    let N = b_max / Math.pow(Cvss_max, n);
    let b = Math.floor(N * Math.pow(Cvss, n));

	if (b < b_min) {
		b = b_min;
	}

	return b;
}

function changeCvssVector() {
  let cvss_vector = document.getElementById("cvss_vector").value;
  let cur_char1; var cur_char2; var cur_char3;
  let i = 0;

  while (i < cvss_vector.length)
  {
    cur_char1 = cvss_vector.charAt(i);
    cur_char2 = cvss_vector.charAt(i + 1);
    cur_char3 = cvss_vector.charAt(i + 2);

    if (cur_char1 == "A" && cur_char2 == "V") {
      let attack_vector = cvss_vector.charAt(i + 3);

      switch (attack_vector) {
        case "N":
          document.getElementById("AV_N").click();
          break;

        case "A":
          document.getElementById("AV_A").click();
          break;

        case "L":
          document.getElementById("AV_L").click();
          break;

        case "P":
          document.getElementById("AV_P").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "A" && cur_char2 == "C") {
      let attack_complexity = cvss_vector.charAt(i + 3);

      switch (attack_complexity) {
        case "L":
          document.getElementById("AC_L").click();
          break;

        case "H":
          document.getElementById("AC_H").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "P" && cur_char2 == "R") {
      let privileges_required = cvss_vector.charAt(i + 3);

      switch (privileges_required) {
        case "N":
          document.getElementById("PR_N").click();
          break;

        case "L":
          document.getElementById("PR_L").click();
          break;

        case "H":
          document.getElementById("PR_H").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "U" && cur_char2 == "I") {
      let user_interaction = cvss_vector.charAt(i + 3);

      switch (user_interaction) {
        case "N":
          document.getElementById("UI_N").click();
          break;

        case "R":
          document.getElementById("UI_R").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "S") {
      let scope = cvss_vector.charAt(i + 2);

      switch (scope) {
        case "U":
          document.getElementById("S_U").click();
          break;

        case "C":
          document.getElementById("S_C").click();
          break;

        default:
          break;
      }

      i += 3;
    } else if (cur_char1 == "C") {
      let confidentiality = cvss_vector.charAt(i + 2);

      switch (confidentiality) {
        case "N":
          document.getElementById("C_N").click();
          break;

        case "L":
          document.getElementById("C_L").click();
          break;

        case "H":
          document.getElementById("C_H").click();
          break;

        default:
          break;
      }

      i += 3;
    } else if (cur_char1 == "I") {
      let integrity = cvss_vector.charAt(i + 2);

      switch (integrity) {
        case "N":
          document.getElementById("I_N").click();
          break;

        case "L":
          document.getElementById("I_L").click();
          break;

        case "H":
          document.getElementById("I_H").click();
          break;

        default:
          break;
      }

      i += 3;
    } else if (cur_char1 == "A") {
      let availability = cvss_vector.charAt(i + 2);

      switch (availability) {
        case "N":
          document.getElementById("A_N").click();
          break;

        case "L":
          document.getElementById("A_L").click();
          break;

        case "H":
          document.getElementById("A_H").click();
          break;

        default:
          break;
      }

      i += 3;
    } else if (cur_char1 == "E") {
      let exploit_code = cvss_vector.charAt(i + 2);

      switch (exploit_code) {
        case "X":
          document.getElementById("E_X").click();
          break;

        case "U":
          document.getElementById("E_U").click();
          break;

        case "P":
          document.getElementById("E_P").click();
          break;

        case "F":
          document.getElementById("E_F").click();
          break;

        case "H":
          document.getElementById("E_H").click();
          break;

        default:
          break;
      }

      i += 3;
    } else if (cur_char1 == "R" && cur_char2 == "L") {
      let remediation_level = cvss_vector.charAt(i + 3);

      switch (remediation_level) {
        case "X":
          document.getElementById("RL_X").click();
          break;

        case "O":
          document.getElementById("RL_O").click();
          break;

        case "T":
          document.getElementById("RL_T").click();
          break;

        case "W":
          document.getElementById("RL_W").click();
          break;

        case "U":
          document.getElementById("RL_U").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "R" && cur_char2 == "C") {
      let remediation_confidence = cvss_vector.charAt(i + 3);

      switch (remediation_confidence) {
        case "X":
          document.getElementById("RC_X").click();
          break;

        case "U":
          document.getElementById("RC_U").click();
          break;

        case "R":
          document.getElementById("RC_R").click();
          break;

        case "C":
          document.getElementById("RC_C").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "C" && cur_char2 == "R") {
      let confidentiality_req = cvss_vector.charAt(i + 3);

      switch (confidentiality_req) {
        case "X":
          document.getElementById("CR_X").click();
          break;

        case "L":
          document.getElementById("CR_L").click();
          break;

        case "M":
          document.getElementById("CR_M").click();
          break;

        case "H":
          document.getElementById("CR_H").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "I" && cur_char2 == "R") {
      let integrity_req = cvss_vector.charAt(i + 3);

      switch (integrity_req) {
        case "X":
          document.getElementById("IR_X").click();
          break;

        case "L":
          document.getElementById("IR_L").click();
          break;

        case "M":
          document.getElementById("IR_M").click();
          break;

        case "H":
          document.getElementById("IR_H").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "A" && cur_char2 == "R") {
      let availability_req = cvss_vector.charAt(i + 3);

      switch (availability_req) {
        case "X":
          document.getElementById("AR_X").click();
          break;

        case "L":
          document.getElementById("AR_L").click();
          break;

        case "M":
          document.getElementById("AR_M").click();
          break;

        case "H":
          document.getElementById("AR_H").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "M" && cur_char2 == "A" && cur_char3 == "V") {
      let modified_attack_vector = cvss_vector.charAt(i + 4);

      switch (modified_attack_vector) {
        case "X":
          document.getElementById("MAV_X").click();
          break;

        case "N":
          document.getElementById("MAV_N").click();
          break;

        case "A":
          document.getElementById("MAV_A").click();
          break;

        case "L":
          document.getElementById("MAV_L").click();
          break;

        case "P":
          document.getElementById("MAV_P").click();
          break;

        default:
          break;
      }

      i += 5;
    } else if (cur_char1 == "M" && cur_char2 == "A" && cur_char3 == "C") {
      let modified_attack_complexity = cvss_vector.charAt(i + 4);

      switch (modified_attack_complexity) {
        case "X":
          document.getElementById("MAC_X").click();
          break;

        case "L":
          document.getElementById("MAC_L").click();
          break;

        case "H":
          document.getElementById("MAC_H").click();
          break;

        default:
          break;
      }

      i += 5;
    } else if (cur_char1 == "M" && cur_char2 == "P" && cur_char3 == "R") {
      let modified_privileges_req = cvss_vector.charAt(i + 4);

      switch (modified_privileges_req) {
        case "X":
          document.getElementById("MPR_X").click();
          break;

        case "N":
          document.getElementById("MPR_N").click();
          break;

        case "L":
          document.getElementById("MPR_L").click();
          break;

        case "H":
          document.getElementById("MPR_H").click();
          break;

        default:
          break;
      }

      i += 5;
    } else if (cur_char1 == "M" && cur_char2 == "U" && cur_char3 == "I") {
      let modified_user_interaction = cvss_vector.charAt(i + 4);

      switch (modified_user_interaction) {
        case "X":
          document.getElementById("MUI_X").click();
          break;

        case "N":
          document.getElementById("MUI_N").click();
          break;

        case "R":
          document.getElementById("MUI_R").click();
          break;

        default:
          break;
      }

      i += 5;
    } else if (cur_char1 == "M" && cur_char2 == "S") {
      let modified_scope = cvss_vector.charAt(i + 3);

      switch (modified_scope) {
        case "X":
          document.getElementById("MS_X").click();
          break;

        case "U":
          document.getElementById("MS_U").click();
          break;

        case "C":
          document.getElementById("MS_C").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "M" && cur_char2 == "C") {
      let modified_confidentiality = cvss_vector.charAt(i + 3);

      switch (modified_confidentiality) {
        case "X":
          document.getElementById("MC_X").click();
          break;

        case "N":
          document.getElementById("MC_N").click();
          break;

        case "L":
          document.getElementById("MC_L").click();
          break;

        case "H":
          document.getElementById("MC_H").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "M" && cur_char2 == "I") {
      let modified_integrity = cvss_vector.charAt(i + 3);

      switch (modified_integrity) {
        case "X":
          document.getElementById("MI_X").click();
          break;

        case "N":
          document.getElementById("MI_N").click();
          break;

        case "L":
          document.getElementById("MI_L").click();
          break;

        case "H":
          document.getElementById("MI_H").click();
          break;

        default:
          break;
      }

      i += 4;
    } else if (cur_char1 == "M" && cur_char2 == "A") {
      let modified_availability = cvss_vector.charAt(i + 3);

      switch (modified_availability) {
        case "X":
          document.getElementById("MA_X").click();
          break;

        case "N":
          document.getElementById("MA_N").click();
          break;

        case "L":
          document.getElementById("MA_L").click();
          break;

        case "H":
          document.getElementById("MA_H").click();
          break;

        default:
          break;
      }

      i += 4;
    }

    i ++;
  }
}

function changeRequiredPrivileges() {
	let select_priv_value = document.getElementById("select_priv_value");
	let select_priv_value_value = select_priv_value.options[select_priv_value.selectedIndex].value;

	switch (select_priv_value_value) {
		case "anonymous":
			document.getElementById("PR_N").click();
			break;
		case "authenticated":
			document.getElementById("PR_L").click();
			break;
		case "authenticated_rights":
			document.getElementById("PR_H").click();
			break;
		case "choose":
			break;
		default:
			alert("Type of privileges not found");
			break;
	}
}

function changeTypeDirectoryListing() {
	let select_directorylisting_cat = document.getElementById("select_directorylisting_cat");
	let select_directorylisting_cat_value = select_directorylisting_cat.options[select_directorylisting_cat.selectedIndex].value;

	switch (select_directorylisting_cat_value) {
		case "directory_sensitive":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "directory_notsensitive":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;

		default:
			alert("Type of directory listing not found");
			break;
	}
}

function changeTypeMisConfigurations() {
	let select_misconfig_cat = document.getElementById("select_misconfig_cat");
	let select_misconfig_cat_value = select_misconfig_cat.options[select_misconfig_cat.selectedIndex].value;

	document.getElementById("misconfiguration_directorylisting_selected").style.display = "none";
	document.getElementById("select_directorylisting_cat").value = "choose";

	switch (select_misconfig_cat_value) {
		case "misconfig_cors":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;

		case "misconfig_path_traversal":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "misconfig_directory_listing":
			document.getElementById("misconfiguration_directorylisting_selected").style.display = "block";

			break;

		case "misconfig_samesitescripting":
			document.getElementById("AV_L").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_C").click();
			document.getElementById("C_L").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;

		case "misconfig_defaultcred":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_H").click();
			document.getElementById("A_L").click();
			break;

		case "misconfig_httmethod":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "misconfig_ssl":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;
		default:
			alert("Type of misconfigurations not found");
			break;
	}
}

function changeTypeAuth() {
	let select_auth_cat = document.getElementById("select_auth_cat");
	let select_auth_cat_value = select_auth_cat.options[select_auth_cat.selectedIndex].value;

	switch (select_auth_cat_value) {
		case "auth_bypass":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_H").click();
			document.getElementById("A_L").click();
			break;

		case "auth_priv":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_H").click();
			document.getElementById("A_N").click();
			break;

		case "auth_session_fixation":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;

		case "auth_invalidate_session":
			document.getElementById("AV_P").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;

		case "auth_concurrent_logins":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;
		default:
			alert("Type of broken authentication not found");
			break;
	}
}

function changeTypeCsrf() {
	let select_csrf_cat = document.getElementById("select_csrf_cat");
	let select_csrf_cat_value = select_csrf_cat.options[select_csrf_cat.selectedIndex].value;

	switch (select_csrf_cat_value) {
		case "csrf_wide":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_L").click();
			document.getElementById("A_L").click();
			break;
		case "csrf_auth":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;
		case "csrf_noauth":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;
		case "csrf_logout":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;
		case "choose":
			break;
		default:
			alert("Type of csrf not found");
			break;
	}
}

function changeTypeFileInclusion() {
	let select_file_inclusion = document.getElementById("select_file_inclusion");
	let select_file_inclusion_value = select_file_inclusion.options[select_file_inclusion.selectedIndex].value;

	document.getElementById("local_file_inclusion_selected").style.display = "none";
	document.getElementById("select_local_file_inclusion").value = "choose";

	switch (select_file_inclusion_value) {
		case "remote_file_inclusion":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_H").click();
			document.getElementById("A_N").click();
			break;
		case "local_file_inclusion":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			document.getElementById("local_file_inclusion_selected").style.display = "block";
			break;
		case "choose":
			break;
		default:
			alert("Type of file inclusion not found");
			break;
	}
}

function changeScopeLocalFileInclusion() {
	let select_local_file_inclusion = document.getElementById("select_local_file_inclusion");
	let select_local_file_inclusion_value = select_local_file_inclusion.options[select_local_file_inclusion.selectedIndex].value;

	switch (select_local_file_inclusion_value) {
		case "local_file_inclusion_changed":
			document.getElementById("S_C").click();
			break;
		case "local_file_inclusion_unchanged":
			document.getElementById("S_U").click();
			break;
		case "choose":
			break;
		default:
			alert("Type of local file inclusion not found");
			break;
	}
}


function changeTypeInjection() {
	let select_injection_cat = document.getElementById("select_injection_cat");
	let select_injection_cat_value = select_injection_cat.options[select_injection_cat.selectedIndex].value;

	document.getElementById("injection_rights").style.display = "none";
	document.getElementById("file_inclusion_selected").style.display = "none";
	document.getElementById("local_file_inclusion_selected").style.display = "none";

	document.getElementById("select_local_file_inclusion").value = "choose";
	document.getElementById("select_file_inclusion").value = "choose";
	document.getElementById("select_injection_rights").value = "choose";

	switch (select_injection_cat_value) {
		case "injection_sqli":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			document.getElementById("injection_rights").style.display = "block";
			break;
		case "injection_rce":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_H").click();
			document.getElementById("A_H").click();
			document.getElementById("injection_rights").style.display = "block";
			break;
		case "injection_file":
			document.getElementById("file_inclusion_selected").style.display = "block";
			break;

		case "injection_httpresp":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;

		case "injection_email":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;
		case "choose":
			break;
		default:
			alert("Type of sqli not found");
			break;
	}
}

function changeScopeInjection() {
	let select_injection_rights = document.getElementById("select_injection_rights");
	let select_injection_rights_value = select_injection_rights.options[select_injection_rights.selectedIndex].value;

	switch (select_injection_rights_value) {
		case "injection_scope_extended":
			document.getElementById("S_C").click();
			break;
		case "injection_scope_same":
			document.getElementById("S_U").click();
			break;
		case "choose":
			break;
		default:
			alert("Type of injection scope not found");
			break;
	}
}

function changeImpactXss() {
	let select_xss_impact = document.getElementById("select_xss_impact_users");
	let select_xss_impact_value = select_xss_impact.options[select_xss_impact.selectedIndex].value;

	switch (select_xss_impact_value) {
		case "xss_impact_noauth":
			document.getElementById("C_N").click();
			document.getElementById("I_L").click();
			document.getElementById("A_L").click();
			break;
		case "xss_impact_auth":
			document.getElementById("C_L").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;
		case "xss_impact_authauto":
			document.getElementById("C_H").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;
		case "choose":
			break;
		default:
			alert("Type of impact xss not found");
			break;
	}
}

function xss_selected_users(value) {
	if (value) {
		document.getElementById("xss_selected_users").style.display = "block";
	} else {
		document.getElementById("xss_selected_users").style.display = "none";
	}
}

function baseXss() {
    
	// dans tout les cas
	// attack vector : network
	// attack complexity : high
	// scope : changed
    
	document.getElementById("AV_N").click();
	document.getElementById("AC_H").click();
	document.getElementById("S_C").click();

	document.getElementById("select_xss_impact_users").value = "choose";
}

function changeTypeXss() {
	let select_xss_cat = document.getElementById("select_xss_cat");
	let select_xss_cat_value = select_xss_cat.options[select_xss_cat.selectedIndex].value;

    baseXss()

	switch (select_xss_cat_value) {
		case "xss_stocked":
			document.getElementById("UI_N").click();
			xss_selected_users(true);
            document.getElementById("select_cwe_cat").value = "cwe79-xsssto";
			break;

		case "xss_reflected":
			document.getElementById("UI_R").click();
            document.getElementById("select_cwe_cat").value = "cwe79-xssref";
			xss_selected_users(true);
			break;

		case "xss_self_reflected":
			xss_selected_users(false);

			document.getElementById("UI_R").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;

		default:
			alert("Type of xss not found");
			break;
	}
}

function changeTypeOpenRedirect() {
	let select_openredirect_cat = document.getElementById("select_openredirect_cat");
	let select_openredirect_cat_value = select_openredirect_cat.options[select_openredirect_cat.selectedIndex].value;

	switch (select_openredirect_cat_value) {
		case "openredirect_get":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;

		case "openredirect_post":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "openredirect_headers":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_R").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;
		default:
			alert("Type of open redirect not found");
			break;
	}
}

function changeTypeHostnameDisclosure() {
	let select_hostnamedisclosure_cat = document.getElementById("select_hostnamedisclosure_cat");
	let select_hostnamedisclosure_cat_value = select_hostnamedisclosure_cat.options[select_hostnamedisclosure_cat.selectedIndex].value;

	switch (select_hostnamedisclosure_cat_value) {
		case "sensitive_hostname":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "notsensitive_hostname":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "wide_hostname":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_C").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;
		default:
			alert("Type of sensitive hostname not found");
			break;
	}
}

function changeTypeIpDisclosure() {
	let select_ipdisclosure_cat = document.getElementById("select_ipdisclosure_cat");
	let select_ipdisclosure_cat_value = select_ipdisclosure_cat.options[select_ipdisclosure_cat.selectedIndex].value;

	switch (select_ipdisclosure_cat_value) {
		case "sensitive_ip":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "notsensitive_ip":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "wide_ip":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;
		default:
			alert("Type of sensitive data not found");
			break;
	}
}

function changeTypeUserEnumeration() {
	let select_userenumeration_cat = document.getElementById("select_userenumeration_cat");
	let select_userenumeration_cat_value = select_userenumeration_cat.options[select_userenumeration_cat.selectedIndex].value;

	switch (select_userenumeration_cat_value) {
		case "sensitive_autouserenumeration":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "sensitive_manuuserenumeration":
			document.getElementById("AV_N").click();
			document.getElementById("AC_H").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;

		default:
			alert("Type of user enumeration not found");
			break;
	}
}

function changeTypeTokenInUrl() {
	let select_typetokeninurl_cat = document.getElementById("select_typetokeninurl_cat");
	let select_typetokeninurl_cat_value = select_typetokeninurl_cat.options[select_typetokeninurl_cat.selectedIndex].value;

	switch (select_typetokeninurl_cat_value) {
		case "sensitive_sensitivetoken":
			document.getElementById("AV_P").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_L").click();
			document.getElementById("I_L").click();
			document.getElementById("A_N").click();
			break;

		case "sensitive_notsensitivetoken":
			document.getElementById("AV_P").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "choose":
			break;

		default:
			alert("Type of token in url not found");
			break;
	}
}

function changeTypeSensitive() {
	let select_sensitive_cat = document.getElementById("select_sensitive_cat");
	let select_sensitive_cat_value = select_sensitive_cat.options[select_sensitive_cat.selectedIndex].value;

	document.getElementById("internalhostnamedisclosure_selected").style.display = "none";
	document.getElementById("internalipdisclosure_selected").style.display = "none";
	document.getElementById("tokeninurl_selected").style.display = "none";
	document.getElementById("user_enumeration_selected").style.display = "none";

	document.getElementById("select_typetokeninurl_cat").value = "choose";
	document.getElementById("select_userenumeration_cat").value = "choose";
	document.getElementById("internalipdisclosure_selected").value = "choose";
	document.getElementById("internalhostnamedisclosure_selected").value = "choose";

	switch (select_sensitive_cat_value) {
		case "sensitive_passworddisclosure":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_H").click();
			document.getElementById("A_L").click();
			break;

		case "sensitive_privateapikeys":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_H").click();
			document.getElementById("I_H").click();
			document.getElementById("A_L").click();
			break;

		case "sensitive_userenumeration":
			document.getElementById("user_enumeration_selected").style.display = "block";
			break;

		case "sensitive_errorpage":
			document.getElementById("AV_N").click();
			document.getElementById("AC_L").click();
			document.getElementById("UI_N").click();
			document.getElementById("S_U").click();
			document.getElementById("C_N").click();
			document.getElementById("I_N").click();
			document.getElementById("A_N").click();
			break;

		case "sensitive_token":
			document.getElementById("tokeninurl_selected").style.display = "block";
			break;

		case "sensitive_internalipdisclosure":
			document.getElementById("internalipdisclosure_selected").style.display = "block";
			break;

		case "sensitive_internalhostnamedisclosure":
			document.getElementById("internalhostnamedisclosure_selected").style.display = "block";
			break;

		case "choose":
			break;

		default:
			alert("Type of sensitive data not found");
			break;
	}
}

 function reset_values() {
	// document.getElementById("select_owasp_cat").value = "choose";
	// document.getElementById("select_priv_value").value = "choose";
	document.getElementById("select_local_file_inclusion").value = "choose";
	document.getElementById("select_file_inclusion").value = "choose";
	document.getElementById("select_injection_rights").value = "choose";
	document.getElementById("select_csrf_cat").value = "choose";
	document.getElementById("select_injection_cat").value = "choose";
	document.getElementById("select_auth_cat").value = "choose";
	document.getElementById("select_sensitive_cat").value = "choose";
	document.getElementById("select_typetokeninurl_cat").value = "choose";
	document.getElementById("select_userenumeration_cat").value = "choose";
	document.getElementById("internalipdisclosure_selected").value = "choose";
	document.getElementById("internalhostnamedisclosure_selected").value = "choose";
	document.getElementById("select_openredirect_cat").value = "choose";
	document.getElementById("select_misconfig_cat").value = "choose";
	document.getElementById("select_directorylisting_cat").value = "choose";
	document.getElementById("select_xss_cat").value = "choose";
	document.getElementById("select_xss_impact_users").value = "choose";
 }

function doHiddenAll() {
	document.getElementById("local_file_inclusion_selected").style.display = "none";
	document.getElementById("file_inclusion_selected").style.display = "none";
	document.getElementById("injection_rights").style.display = "none";
	document.getElementById("xss_selected").style.display = "none";
	document.getElementById("xss_selected_users").style.display = "none";
	document.getElementById("csrf_selected").style.display = "none";
	document.getElementById("injection_selected").style.display = "none";
	document.getElementById("openredirect_selected").style.display = "none";
	document.getElementById("auth_selected").style.display = "none";
	document.getElementById("misconfiguration_selected").style.display = "none";
	document.getElementById("misconfiguration_directorylisting_selected").style.display = "none";
	document.getElementById("sensitivedataexposure_selected").style.display = "none";
	document.getElementById("internalipdisclosure_selected").style.display = "none";
	document.getElementById("internalhostnamedisclosure_selected").style.display = "none";
	document.getElementById("tokeninurl_selected").style.display = "none";
	document.getElementById("user_enumeration_selected").style.display = "none";

	document.getElementById("AV_N").click();
	document.getElementById("AC_L").click();
	// document.getElementById("PR_N").click();
	document.getElementById("UI_N").click();
	document.getElementById("S_U").click();

	document.getElementById("C_N").click();
	document.getElementById("I_N").click();
	document.getElementById("A_N").click();

	document.getElementById("E_X").click();
	document.getElementById("RL_X").click();
	document.getElementById("RC_X").click();
	/*
	document.getElementById("CR_X").click();
	document.getElementById("IR_X").click();
	document.getElementById("AR_X").click();

	document.getElementById("MAV_X").click();
	document.getElementById("MAC_X").click();
	document.getElementById("MPR_X").click();
	document.getElementById("MUI_X").click();
	document.getElementById("MS_X").click();
	document.getElementById("MC_X").click();
	document.getElementById("MI_X").click();
	document.getElementById("MA_X").click();
	*/
	reset_values();
}

function doXee() {
	document.getElementById("AV_N").click();
	document.getElementById("AC_L").click();
	document.getElementById("UI_N").click();
	document.getElementById("S_U").click();
	document.getElementById("C_H").click();
	document.getElementById("I_L").click();
	document.getElementById("A_N").click();
}

function doXss() {
	let node = document.getElementById("xss_selected");
	node.style.display = "block";
}

function doInjection() {
	let node = document.getElementById("injection_selected");
	node.style.display = "block";
}

function doCsrf() {
	let node = document.getElementById("csrf_selected");
	node.style.display = "block";
}

function doOpenredirect() {
	let node = document.getElementById("openredirect_selected");
	node.style.display = "block";
}

function doAuth() {
	let node = document.getElementById("auth_selected");
	node.style.display = "block";
}

function doMisconfiguration() {
	let node = document.getElementById("misconfiguration_selected");
	node.style.display = "block";
}

function doDataexposure() {
	let node = document.getElementById("sensitivedataexposure_selected");
	node.style.display = "block";
}


function changeTypeWeakness()
{
	let select_cwe_cat = document.getElementById("select_cwe_cat");
	let select_cwe_cat_value = select_cwe_cat.options[select_cwe_cat.selectedIndex].value;

	doHiddenAll();
    document.getElementById("select_owasp_cat").value = "choose";

	document.getElementById("E_H").click();
	document.getElementById("RL_U").click();
	document.getElementById("RC_C").click();
            
	switch (select_cwe_cat_value) {
		case "cwe79-xssdom":
			doXss();
            document.getElementById("select_owasp_cat").value = "xss";
            document.getElementById("select_xss_cat").value = "xss_reflected";
            baseXss();
			document.getElementById("UI_R").click();
			xss_selected_users(true);
			break;
		case "cwe79-xssgen":
			doXss();
            document.getElementById("select_owasp_cat").value = "xss";
            document.getElementById("select_xss_cat").value = "xss_reflected";
            baseXss();
			xss_selected_users(true);
			break;
		case "cwe79-xssref":
			doXss();
            document.getElementById("select_owasp_cat").value = "xss";
            document.getElementById("select_xss_cat").value = "xss_reflected";
            baseXss();
			document.getElementById("UI_R").click();
			xss_selected_users(true);
			break;
		case "cwe79-xsssto":
			doXss();
            document.getElementById("select_owasp_cat").value = "xss";
            document.getElementById("select_xss_cat").value = "xss_stocked";
            baseXss();
			document.getElementById("UI_N").click();
			xss_selected_users(true);
			break;
		case "choose":
			break;
		default:
			alert("catégorie cwe introuvable");
			break;
	}
}

function changeTypeVuln()
{
	let select_owasp_cat = document.getElementById("select_owasp_cat");
	let select_owasp_cat_value = select_owasp_cat.options[select_owasp_cat.selectedIndex].value;

	doHiddenAll();
    document.getElementById("select_cwe_cat").value = "choose";

	document.getElementById("E_H").click();
	document.getElementById("RL_U").click();
	document.getElementById("RC_C").click();

	switch (select_owasp_cat_value) {
		case "xee":
			doXee();
			break;
		case "xss":
			doXss();
			break;
		case "injection":
			doInjection();
			break;
		case "csrf":
			doCsrf();
			break;
		case "auth":
			doAuth();
			break;
		case "misconfiguration":
			doMisconfiguration();
			break;
		case "dataexposure":
			doDataexposure();
			break;
		case "openredirect":
			doOpenredirect();
			break;
		case "choose":
			break;
		default:
			alert("catégorie owasp introuvable");
			break;
	}
 }

function FindProxyForURL(url, host)
{
//PAC FILE
//Git Version 9909a2175ed09916a869d19e3253b0f6e5f2a61c
//==============================  Proxy Rules  ==============================
	if (shExpMatch(host, "hs.healthstream.com"))  /*  10-25-18 - Site has to go direct and be above *.healthstream.com, SCTASK000032088 */
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "carelink.force.com"))  /* 3-1-19 - Moved from top to just aboveforce.com - CHG0056454 */
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "static.lightning.force.com"))  /* 3-1-19 - Emergency PAC file change. Site works through proxy and using Akamai now - CHG0056454 */
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "portal.ehc.medcity.net"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "portalqa.ehc.medcity.net"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "fwfilp01.ftw.medcity.net"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "elearning.medcity.net"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "events.parallon.net"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "events.parallon.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "my.parallon.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "fileconnect.parallon.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "fileconnectservice.parallon.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "webinars.parallon.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "information.parallon.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "go.parallon.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "careers.parallon.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "www.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "video.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "dataintake.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "survey.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "totalspendmanagement.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "go.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "events.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "webinars.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "hsevents.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "education.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "events.coretrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "go.coretrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "webinars.coretrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "careers.healthtrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "www.coretrustpg.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "performancemanager4.successfactors.com"))  /**/
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "www.clinicalpharmacology-ip.com"))  /*  ORL WSA Host Exceptions  */
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "clinicalpharmacology-ip.com"))  /*  ORL WSA Host Exceptions  */
		return "PROXY proxy.tpa.medcity.net:80";
	if (shExpMatch(host, "supersteve2.com"))  /*  Test  */
		return "PROXY proxy.tpa.medcity.net:80";
//=============================  Direct Rules  ==============================
	if (shExpMatch(host, "healthstream.skillport.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "healthstream.skillsoft.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "library.skillport.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "healthstream.skillwsa.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.cmecourses.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.eddesign.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mentoru.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.1ar.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "64.32.238.166"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "67.32.159.29"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "207.3.151.37"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "208.110.206.101"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "citrix.ahcinc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.biogenidec.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hca.centra.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hca.centra.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.centrinet.biz"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.compplanner.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.easylink.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.ecaos.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehctxnfs.ehr.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcaasp001.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcafs01.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcacognos.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "tumgapp001.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "health.state.tn.us"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.elabcorp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "irl.elaborders.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hca.esign.e-mtsonline.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.etenet.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.evolvelearning.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.fujipacs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hcaview.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hewitt.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hospitalcompare.hhs.gov"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hrts.state.tn.us"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "icu.ehc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.icu.ehc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "lpm.videotrainer.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.i-dep.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "insidemhs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.insidemhs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "admin.icare.intellicare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "iap.icare.intellicare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "iap.intellicare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.medconnect.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.medstat.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mhscentral.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mhscentral.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.med.miami.edu"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.myberyl.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mytracked.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mytricare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mytricare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.osmcore.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pacsweb.carilion.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.practicelink.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.procuri.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pss-i.signaturehospital.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.resx.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.rsoc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.safekeeperplus.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hdcb.tenethealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.sodexhoinfo-usa.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.starsasp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.strohlservices.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.tn.gov"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "tn.gov"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.tennessee.gov"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "tennessee.gov"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "trialbuild.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.tsystem.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.teachandtrack.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "HRMSweb.tenethealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mytch.thechildrenshospital.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.usoncology.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.visionsolutions.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.vssidatasolutions.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.wesrdc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "zcom.amerisource.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.forensicsconsulting.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mrinetsource.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.healthdesigngroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.floridaopenimaging.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "astute.cardiosource.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cardiosource.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "shap.sironahealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "Elink.texashealth.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cag2.texashealth.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.atsmedia.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "link26.streamhoster.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcaapp002.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.stream57.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hillsidepacs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hillsidepacs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcaapp003.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cokergroup.basecamphq.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.update.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "update.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "64.19.40.194"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "70.184.231.139"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.trainingadvisorinc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "trainingadvisorinc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "app1.impacasp.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "admin.intersourcing.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sgsha.intersourcing.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "www52.intersourcing.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.chartvault.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "chartvault.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.ewebhealth.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ewebhealth.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "procurementsuiteintegration.ghx.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "portal.mobilfone.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.marymount.edu"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "marymount.edu"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hraserv1.traleexplorer.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcaqol.corpqol.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hcaqol.corpqol.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hcapf.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "remotedeposit.bankofamerica.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.remotedeposit.bankofamerica.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "remotedeposit-cashpro.bankofamerica.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.remotedeposit-cashpro.bankofamerica.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.emdeon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "emdeon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "access.webmd.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcaview.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hcaview.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "CardinalSupportConnect.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.CardinalSupportConnect.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "racinfo.healthdatainsights.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pacs*.thomaswv.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.wkhpe.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "wkhpe.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "djcs.marketwatch.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "chart.bigcharts.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "97.74.32.25"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "140.239.90.226"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.237.251.211"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hca.erexasp1.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "askmike.infinittna.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "surescripts.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.webtma.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "67.214.102.60"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "webtma.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "SystemDiagnostics.apisoftwareinc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "redmedical.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.redmedical.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mytelevox.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mytelevox.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mdiachieve.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mdiachieve.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "166.102.234.105"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mediquantdataark.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mediquantdataark.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hpg-spend.bravosolution.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "32.80.199.200"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "32.71.31.182"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cosfmrapp.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cosfmrebo.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cosfmrftp.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.crimsonservices.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "crimsonservices.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "emsc.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.emsc.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hca.intellicure.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.sarahcannoncancer.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sarahcannoncancer.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.myscri.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "myscri.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hcacorpqol.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcacorpqol.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "surescripts.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.surescripts.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "chartlink.mch-ok.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "eclinicalworks.tulane.edu"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.ptshost.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "casemanagementconference.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.casemanagementconference.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "acmaweb.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.acmaweb.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "txgeomapp.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "txbcfpapp.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "labcorp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.labcorp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "107.23.133.171"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "107.23.4.7"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcacie.sharepoint.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.trajecsys.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "trajecsys.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "holterz.lifewatch.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.visionshareinc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "visionshareinc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehctest.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.ehctest.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehcstaging.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.ehcstaging.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ftp2.fristcenter.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "studergroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.studergroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.vzaar.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "vzaar.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "olderadultfallscoalitionco.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.olderadultfallscoalitionco.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "follettice.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.follettice.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "secure.mquiq.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "seappext1.astrazeneca.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "seappext2.astrazeneca.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sgappext1.astrazeneca.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sgappext2.astrazeneca.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "usappext1.astrazeneca.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "usappext2.astrazeneca.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "primrosemed.exavault.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "lillynetcollaboration.global.lilly.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "www.am.azcollaboration.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "www.em.azcollaboration.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "www.ap.azcollaboration.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "tsgateway.intellicure.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "view.ou.edu"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "formulary.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "rxhub.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "accuray-prod.clinovo.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "clinovo.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.clinovo.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sbamh.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sbamh-sslvpn.sbamh.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "206.54.106.162"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hotsprings.veedis.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "capella.veedis.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "triad-dir.acr.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "heartbeat.primordialdesign.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "novoinnovations.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.novoinnovations.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "paraccess.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*paraccess.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "trainingmedia.esri.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.trainingmedia.esri.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "interpretrac.lsaweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "connect.ouphysicians.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "fmxdev.hcafi.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "qa.hcafi.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "fmxstaging.hcafi.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "fmx.hcafi.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "csctest.relayhealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "rds1.relayhealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "shcr.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.shcr.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "tmsonline.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.tmsonline.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ed.grammarly.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "capi.grammarly.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "api.mixpanel.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "api.parse.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "184.106.77.70"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mediasite.shmc.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "escription.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.escription.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "medstarimageshare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.medstarimageshare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ucce.local"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.ucce.local"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "nettime.centralservers6.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.nettime.centralservers6.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "salesforce.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.salesforce.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "force.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.force.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "staticforce.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.staticforce.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cqi.armus.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "o3-cloud.armus.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "secure.athenahealthpayment.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.myscridev.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "myscridev.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.myscriqa.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "myscriqa.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.myscri.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "myscri.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "portal.emsc.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "successfactors.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.successfactors.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ths-ps*.thomaswv.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "secure.ahin-net.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "medicaid.state.ar.us"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "medicaloutreachcorp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.medicaloutreachcorp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "asp.orderfacilitator.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.insitescloud.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "insitescloud.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.accreditcoach.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "accreditcoach.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.kp.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "kp.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.medicaider.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "medicaider.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.udsmr.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "udsmr.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.carelearning.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "carelearning.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.carelearningsupport.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "carelearningsupport.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mycl.us"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mycl.us"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "rds.kamtechnologies.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.chartwisemed.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "chartwisemed.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.truecode.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "truecode.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.successfactors.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "successfactors.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.nmci.nvay.mil"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "nmci.navy.mil"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.meridianhcs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "meridianhcs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.cloud.infor.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cloud.infor.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.cinemark.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cinemark.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "secure8.oncoemr.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.onlineistream.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "onlineistream.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.tractmanager.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "tractmanager.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.meditract.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "meditract.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pacs.caimri.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.systocemr.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pacs.rockymountainradiologists.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "xnet.kp.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hca.onsite.perfectomobile.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.medstrat.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "medstrat.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pwx.cernerworks.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sc.mahc.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mcc.rutherfordregional.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mcc.rutherfordregional.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ive-ssdc.kp.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ive-wdc.kp.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ive-crdc.kp.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.powerdms.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "powerdms.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.divrad.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "divrad.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.stagehop.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "stagehop.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.powerdmslocal.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "powerdmslocal.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "webauth.lpnt.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "prod1.flexibleinformatics.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "autodiscover.hcahealthcare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcapsg.coi-smart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "oklahomauniv.impress-connect.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "intergrationservices.mysurgicaltracking.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.sodexhoinfo-usa.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sodexhoinfo-usa.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "staging.myclearbalance.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "securemail.pathgroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "noc2.insitescloud.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "uploads.koffel.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcapcare.imhxpc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcasshist.imhxpc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcarxhxmt.imhxpc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcautils.imhxpc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.myhealthone.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "myhealthone.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.accreditcoach.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "accreditcoach.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.colorbarexpress.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "colorbarexpress.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "staging.verid.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "stagingcert.verid.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "netview.verid.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "netviewcert.verid.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.billoreilly.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "billoreilly.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.catalyze.io"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "catalyze.io"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "registry.npmjs.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "clickonce-prod.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehrlogin1.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehrprod1.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehrimages.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehrupload.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehrcqm.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "webservices.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehrpatientportal.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "portalservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "dataportabilityservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "patientservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "userservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "practiceservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "messageservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "vocabularyservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "reportingservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "auditservice.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehrprod2.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "util.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "diag.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "prod4.nash.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "prod5.nash.digichart.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "healthcare.siemens.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ftp.fdbhealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.device.kitcheck.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "portal.tranow.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.magnushealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "magnushealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pacs.intelemage.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "lsaadmin.cenero.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "r1.cenero.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "r2.cenero.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.sendthisfile.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sendthisfile.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "buffalo.edu"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.med.buffalo.edu"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "med.buffalo.edu"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.marchforbabies.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "marchforbabies.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "webapps.sths.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "iv.riaco.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.cpmhealthgrades.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cpmhealthgrades.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "providerportal.tsghealthcare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "apps.cthosp.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.cernerlearningmanager.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cernerlearningmanager.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ehconnect.ascensionhealth.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.portal.medcity.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ascension.kronoshosting.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "idm2-prod-dmz.ascensionhealth.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "prod.ccs.carenow"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cqw.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "teletracking-dev.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "cl-teletracking.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "provisioning.ascensionhealth.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "aas-tnnas.ascensionhealth.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "symphonyguides.ascension.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "licensing.services.sage.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "outlook.divrad.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.myabilitynetwork.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "myabilitynetwork.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.imbills.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "imbills.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.imone.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "imone.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "bam.nr-data.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "smg.omes.ok.gov"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mrimobile.clockapp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "NFDVWPINSBIA01.hca.corpad.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sso-ascn-prd.tc.workstreaminc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "iheal.healogics.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ftp.transcriptiongear.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "intranet.divrad.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.vidistar.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "vidistar.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pointclickcare.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.pointclickcare.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "login.pointclickcare.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.login.pointclickcare.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "empoweredbenefits.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.empoweredbenefits.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mygilsbar.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mygilsbar.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "its.emdeon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "salterlabs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.salterlabs.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mdnetsolutions.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mdnetsolutions.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "download.vsee.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "vsee.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mdlive.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mdlive.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "lb.edge.stratusvideo.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "gda.ascension.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "goodday.ascension.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "broker.rockymountaingastro.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "gateway.rockymountaingastro.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "wts01.rockymountaingastro.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "wts02.rockymountaingastro.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "wts03.rockymountaingastro.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "wts04.rockymountaingastro.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.taleo.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "taleo.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.onlineproviderservices.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "onlineproviderservices.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.palmettogba.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "palmettogba.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.novatuscontracts.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "novatuscontracts.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.curaspan.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "curaspan.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.edischarge.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "edischarge.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.bicsi.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "bicsi.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.complyos.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "complyos.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "complyos-host.facilitiapp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "complyos.facilitiapp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.facilitiapp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "facilitiapp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "simplee.tripos.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "services.softscript.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hospital.softscript.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "h.softscript.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hca.relayhealth.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "training.sandhillstech.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.escriptionasp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "escriptionasp.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.escriptiontest.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "escriptiontest.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.elementexpress.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "elementexpress.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "portal.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mail.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ps360.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "speedtest.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "emageon.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "prod-emageon.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sec-emageon.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "intranet.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "worklist.foundationradiologygroup.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "d11zp3ft26v32f.cloudfront.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "aiscomms.ascension.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "idm-prodoia.ascensionhealth.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "atrack.alsco.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "portal.medwesthealth.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "123.123.123.232"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "123.123.123.225"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "stfrancis.safechx.crosschx.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "stfrancis.quad.crosschx.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "myvirtualworkplace.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "fauqb2b.fauquierhospital.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "iweb2.ccf.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "prod.registryanywhere.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.registryanywhere.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "registryanywhere.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sr.symcd.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "myportal.mynovant.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "170.71.7.96"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "170.71.7.97"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "wiproxy.ccf.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "rips360prod.romemed.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "rips360test.romemed.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "lahhmgapp.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pacs.sportmed.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "qcctx01.qbsol.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "apps.usiis.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "healthtrustws.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.healthtrustws.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "healthtrustws.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "nightingaleluminary.awardsplatform.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "txhshcapp.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "sctnlpapp.eclinicalweb.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.204.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.205.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.206.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.207.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.51.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.54.69"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "nhs.woundexpert.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "reviewpoint.afmc.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "z1y7a2tno5p7v6LF.afmc.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.egnyte.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "appweb.tnonc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "copiaweb.tnonc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "intranet.tnonc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "lyncdiscoverinternal.hcahealthcare.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "glde0hkp1.rsodm20.smsrsm.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "edit.boxlocalhost.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "fs.fsprod"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.fsprod"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mckesson.subscribenet.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mckc-esd.subscribenet.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ths-cdsfax.thomaswv.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.regionalcare.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.20.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.21.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.22.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "168.85.23.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hcaukqa01.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hca.uk.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcaukqa01.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hca.uk.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "xensf.covhlth.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "kpmgleasingtool.kpmg.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "services.vtoxford.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.onestreamcloud.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "services.vtoxford.org"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.97"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.63"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.76"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.64"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.49"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.65"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.50"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.51"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.85"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.52"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.66"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.53"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "159.140.175.190"))  /* 5-10-18 - IPs used as a local IPs at Citrus Memorial, WO0000005722390 */
		return "DIRECT";
	if (shExpMatch(host, "connectvdi.ad.baptistfirst.org"))  /* 5-10-18 - DNS resolves to IP for B2B, WO0000005560774 */
		return "DIRECT";
	if (shExpMatch(host, "bhvdicb01.ad.baptistfirst.org"))  /* 5-10-18 - DNS resolves to IP for B2B, WO0000005560774 */
		return "DIRECT";
	if (shExpMatch(host, "bhvdicb02.ad.baptistfirst.org"))  /* 5-10-18 - DNS resolves to IP for B2B, WO0000005560774 */
		return "DIRECT";
	if (shExpMatch(host, "THOMCDSFAX*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "THOMBEDSTAT*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "THOMPSSQL*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "THOMPSTST*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "THOMINQAP*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, " THOMTDOCAP*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "THOMTDOCTST*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "THOMDOCAIDE*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "THOMRPT*.thomaswv.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "ghsapps.geisinger.edu"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "abacus.carenet.org"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "empowerid.lph.lifepointhealth.net"))  /* 6-28-18 - DNS resolves to local host at ThomasHealth facility, WO0000006023973 */
		return "DIRECT";
	if (shExpMatch(host, "connectvdi.ad.baptistfirst.org"))  /*  10-25-18 -  Site resolves to local B2B IP, SCTASK000023296 */
		return "DIRECT";
	if (shExpMatch(host, "bhvdicb01.ad.baptistfirst.org"))  /*  10-25-18 -  Site resolves to local B2B IP, SCTASK000023296 */
		return "DIRECT";
	if (shExpMatch(host, "bhvdicb02.ad.baptistfirst.org"))  /*  10-25-18 -  Site resolves to local B2B IP, SCTASK000023296 */
		return "DIRECT";
	if (shExpMatch(host, "*.cldazdev.net"))  /*  12/20/18 -  Internal AD domains for  Azure hosted servers, SCTASK000041422*/
		return "DIRECT";
	if (shExpMatch(host, "*.cldazqa.net"))  /*  12/20/18 -  Internal AD domains for  Azure hosted servers, SCTASK000041422*/
		return "DIRECT";
	if (shExpMatch(host, "*.cldaz.net"))  /*  12/20/18 -  Internal AD domains for  Azure hosted servers, SCTASK000041422*/
		return "DIRECT";
	if (shExpMatch(host, "medcity.locus-health.com"))  /*  12/20/18 -  Site resolves to internal IP address, SCTASK000060217*/
		return "DIRECT";
	if (shExpMatch(host, "primordial.bo.trinity-health.org"))  /*  12/20/18 -  Site resolves to internal IP address, SCTASK000083466*/
		return "DIRECT";
	if (shExpMatch(host, "primordialsearch.bo.trinity-health.org"))  /*  12/20/18 -  Site resolves to internal IP address, SCTASK000083466*/
		return "DIRECT";
	if (shExpMatch(host, "trayapp.smartcorp.net"))  /* 2/21/19- vendor app resolves to 127.0.0.1, SCTASK000033439  */
		return "DIRECT";
	if (shExpMatch(host, "oumi.cerebrosapp.com"))  /*  2/21/19 - DNS used over B2B tunnel, SCTASK000090179 */
		return "DIRECT";
	if (shExpMatch(host, "oumi.staging.cerebrosapp.com"))  /*  2/21/19 - DNS used over B2B tunnel, SCTASK000090179 */
		return "DIRECT";
	if (shExpMatch(host, "ps360.riaco.com"))  /*  3-28-19 - vendor application does not work with proxies. No other option but to bypass. INC001451066 */
		return "DIRECT";
	if (shExpMatch(host, "reports.ehc.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "127.0.0.1"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "10.*.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.32.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.33.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.34.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.35.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.36.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.37.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.38.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.39.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.40.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.41.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.42.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.43.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.44.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.45.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.46.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.7.47.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.41.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.42.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.97.4.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "20.97.5.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "50.*.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "152.10.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "170.150.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "170.229.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "170.1.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.25.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.23.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.22.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.21.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.20.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.19.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.18.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.17.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "172.16.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "192.168.*.*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "localhost"))  /**/
		return "DIRECT";
	if (isPlainHostName(host))  /**/
		return "DIRECT";
	if (shExpMatch(host, "66.28.40.177*"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.medcity.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.columbia.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.colhca.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.corpad.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.corpaddev.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.corpadqa.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hcaqa.corpadqa.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.hcacollab.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.triadhospitals.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "apps*.triview.triadhospitals.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.corp.care"))  /*  10-25-18- Parallon OSB sites, local 10. addresses used, SCTASK000019378 */
		return "DIRECT";
	if (shExpMatch(host, "workforcetest.parallon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "workforce.parallon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "workforcedev.parallon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "workforceload.parallon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "workforcedemo.parallon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.parallonqa.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "parallonqa.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.parallon.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "parallon.net"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.parallon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "parallon.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "nsj1msccl01.webex.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "nsj1wss.webex.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "hcatraining.webex.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "pws.webex.com"))  /*  7-26-18 - New Parallon Internal WebEx, WO0000006413143  */
		return "DIRECT";
	if (shExpMatch(host, "parallontechnology.webex.com"))  /*  8-21-18 - Parallon Technology  WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "hcaukmeeting.webex.com"))  /*  8-21-18 - HCA UK WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "mhb.webex.com"))  /*  8-21-18 - Mobile Heartbeat WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "parallontraining.webex.com"))  /*  8-21-18 - Parallon Training WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "healthtrustws.webex.com"))  /*  8-21-18 - Healthtrust Workforce Solutions WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "hws.webex.com"))  /*  8-21-18 - Healthtrust Workforce Solutions WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "hca-test.webex.com"))  /*  8-21-18 - HCA Testing Center WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "hcasupport.webex.com"))  /*  8-21-18 - HCA Support Center WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "healthtrust.webex.com"))  /*  8-21-18 - Healthtrust WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "hcamcssotesting.webex.com"))  /*  8-21-18 - HCA SSO Testing WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "hcaconnecttrain.webex.com"))  /*  8-21-18 - HCA Connect Training Center WebEx, WO0000006484361 */
		return "DIRECT";
	if (shExpMatch(host, "*.healthtrustpg.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.mygpo.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "mygpo.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "*.coretrustpg.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "useradmin.asp.siemensmedical.com"))  /**/
		return "DIRECT";
	if (shExpMatch(host, "ascend.msj.org"))  /*  5-30-19 - site resolves to local 10. IP address, SCTASK000227393  */
		return "DIRECT";
	if (shExpMatch(host, "missionpoint.msj.org"))  /*  5-30-19 - site resolves to local 10. IP address, SCTASK000227393  */
		return "DIRECT";
	if (shExpMatch(host, "thostlocal.tandemdiabetes.com"))  /*  5-30-19 - site resolves to 127.0.0.1, RITM000184723  */
		return "DIRECT";
	if (shExpMatch(host, "170.71.215.122"))  /*  9/12/19 - IP is used at a facility, SCTASK000327808  */
		return "DIRECT";
	if (shExpMatch(host, "nip.io"))  /*  9/12/19 - Application redirects to a local IP. SCTASK000310199  */
		return "DIRECT";
	if (shExpMatch(host, "*.nip.io"))  /*  9/12/19 - Application redirects to a local IP. SCTASK000310199  */
		return "DIRECT";
	if (shExpMatch(host, "hcacwqacertsync.cernerhie.org"))  /*  1/23/19 - multiple users over multiple ports - SCTASK000521908  */
		return "DIRECT";
	if (shExpMatch(host, "hcacwprodsync.cernerhie.org"))  /*  1/23/19 - multiple users over multiple ports - SCTASK000521908  */
		return "DIRECT";
	if (shExpMatch(host, "api2.heartlandportico.com"))  /*  1/23/2020 - New enterprise credit card app. Vendor does not support proxies. -  SCTASK000519606  */
		return "DIRECT";
	if (shExpMatch(host, "rdg101294b2b.nextgenmcs.com"))  /*  URL Resolves to internal NAT addresses 10.65.89.114 & 10.65.89.113  */
		return "DIRECT";
	if (shExpMatch(host, "166.130.54.40"))  /*  Change to application causes the application to inherit proxy settings for updates but does not allow access over proxy servers  */
		return "DIRECT";
	if (shExpMatch(host, "107.85.98.93"))  /*  Change to application causes the application to inherit proxy settings for updates but does not allow access over proxy servers  */
		return "DIRECT";
	if (shExpMatch(host, "166.167.211.86"))  /*  Change to application causes the application to inherit proxy settings for updates but does not allow access over proxy servers  */
		return "DIRECT";
//=========================  Clean-Up Rule, everything else goes to the proxy  =========================
return "PROXY proxy.tpa.medcity.net:80";
}
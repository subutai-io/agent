#!groovy

notifyBuildDetails = ""
agentCommitId = ""

try {
	notifyBuild('STARTED')
	node("deb") {
		deleteDir()
     
		stage("Checkout source")
		
		notifyBuildDetails = "\nFailed on Stage - Checkout source"
				
		String date = new Date().format( 'yyyyMMddHHMMSS' )
		def CWD = pwd()

                switch (env.BRANCH_NAME) {
                    case ~/master/: 
                        cdnHost = "masterbazaar.subutai.io"; 
                        break;
                    case ~/dev/: 
                        cdnHost = "devbazaar.subutai.io"; 
                        break;
                    case ~/no-snap/: 
                        cdnHost = "devbazaar.subutai.io"; 
                        break;
                    case ~/sysnet/: 
                        cdnHost = "sysnetbazaar.subutai.io"; 
                        break;
                    default: 
                        cdnHost = "bazaar.subutai.io"; 
                }
                def release = env.BRANCH_NAME

		sh """
			#set +x
			export LC_ALL=C.UTF-8
			export LANG=C.UTF-8
			rm -rf *
			cd ${CWD} || exit 1

			# Clone agent code
			git clone https://github.com/subutai-io/agent
			cd agent
			git checkout ${release}
		"""		
		stage("Tweaks for version")
		notifyBuildDetails = "\nFailed on Stage - Version tweaks"
		sh """
                        cd ${CWD}/agent || exit 1
                        agent_version=\$(git describe --abbrev=0 --tags)+\$(date +%Y%m%d%H%M%S0)
			echo "VERSION is \$agent_version"

			cd ${CWD}/agent && sed -i 's/quilt/native/' debian/source/format
                        cd ${CWD}/agent && sed -i 's/@cdnHost@/${cdnHost}/' debian/tree/agent.conf
			dch -v "\$agent_version" -D stable "Test build for \$agent_version" 1>/dev/null 2>/dev/null
		"""

		stage("Build Agent package")
		notifyBuildDetails = "\nFailed on Stage - Build package"
		sh """
			cd ${CWD}/agent
			dpkg-buildpackage -rfakeroot

			cd ${CWD} || exit 1
			for i in *.deb; do
    		            echo '\$i:';
    		            dpkg -c \$i;
			done
		"""
		
		stage("Upload Packages")
		notifyBuildDetails = "\nFailed on Stage - Upload"
		sh """
			cd ${CWD}
			touch uploading_agent
			scp uploading_agent subutai*.deb dak@deb.subutai.io:incoming/${release}/
			ssh dak@deb.subutai.io sh /var/reprepro/scripts/scan-incoming.sh ${release} agent
		"""
	}

} catch (e) { 
	currentBuild.result = "FAILED"
	throw e
} finally {
	// Success or failure, always send notifications
	notifyBuild(currentBuild.result, notifyBuildDetails)
}

// https://jenkins.io/blog/2016/07/18/pipline-notifications/
def notifyBuild(String buildStatus = 'STARTED', String details = '') {
  // build status of null means successful
  buildStatus = buildStatus ?: 'SUCCESSFUL'

  // Default values
  def colorName = 'RED'
  def colorCode = '#FF0000'
  def subject = "${buildStatus}: Job '${env.JOB_NAME} [${env.BUILD_NUMBER}]'"  	
  def summary = "${subject} (${env.BUILD_URL})"

  // Override default values based on build status
  if (buildStatus == 'STARTED') {
    color = 'YELLOW'
    colorCode = '#FFFF00'  
  } else if (buildStatus == 'SUCCESSFUL') {
    color = 'GREEN'
    colorCode = '#00FF00'
  } else {
    color = 'RED'
    colorCode = '#FF0000'
	summary = "${subject} (${env.BUILD_URL})${details}"
  }
  // Get token
  def slackToken = getSlackToken('sysnet')
  // Send notifications
  slackSend (color: colorCode, message: summary, teamDomain: 'optdyn', token: "${slackToken}")
}

// get slack token from global jenkins credentials store
@NonCPS
def getSlackToken(String slackCredentialsId){
	// id is ID of creadentials
	def jenkins_creds = Jenkins.instance.getExtensionList('com.cloudbees.plugins.credentials.SystemCredentialsProvider')[0]

	String found_slack_token = jenkins_creds.getStore().getDomains().findResult { domain ->
	  jenkins_creds.getCredentials(domain).findResult { credential ->
	    if(slackCredentialsId.equals(credential.id)) {
	      credential.getSecret()
	    }
	  }
	}
	return found_slack_token
}

#!groovy

notifyBuildDetails = ""
agentCommitId = ""
agentVersion = ""

try {
	notifyBuild('STARTED')
	node("deb") {
		deleteDir()
     
		stage("Checkout source")
		
		notifyBuildDetails = "\nFailed on Stage - Checkout source"
				
		String date = new Date().format( 'yyyyMMddHHMMSS' )
		def VER = "6.4.12+${date}"
		def CWD = pwd()
		sh """
			#set +x
			export LC_ALL=C.UTF-8
			export LANG=C.UTF-8
			rm -rf *
			cd ${CWD} || exit 1

			# Clone agent code
			git clone https://github.com/subutai-io/agent
			cd agent
			git checkout --track origin/no-snap && rm -rf .git*
			cd ${CWD}|| exit 1

			# Clone debian packaging
		
			git clone https://github.com/happyaron/subutai-agent

			# Put debian directory into agent tree
			cp -r subutai-agent/debian/ agent/
			echo "Copied debian directory"

		"""		
		stage("Tweaks for version")

		sh """
			
			echo 'VERSION is ${VER}'
			cd agent && sed -i 's/quilt/native/' debian/source/format
			dch -v '${VER}' -D stable 'Test build for ${VER}' 1>/dev/null 2>/dev/null

		"""

		stage("Build package")
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
		stage("Upload")
		notifyBuildDetails = "\nFailed on Stage - Upload"
		sh """
			touch uploading_agent
			scp uploading_agent subutai*.deb dak@deb.subutai.io:incoming/
			ssh dak@deb.subutai.io sh /var/reprepro/scripts/scan-incoming.sh agent
		"""
		stage("Clean Up")
		sh """
			echo 'Done'
			#cd ${CWD} /.. && rm -rf ${CWD}
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
  def slackToken = getSlackToken('sysnet-bots-slack-token')
  // Send notifications
  // slackSend (color: colorCode, message: summary, teamDomain: 'subutai-io', token: "${slackToken}")
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
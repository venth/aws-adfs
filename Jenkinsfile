#!groovy
@Library("platform.infrastructure.jenkinslib")
import com.ebsco.platform.Shared

node("docker") {

  // Create a groovy library object from the Shared.groovy file.
  def shared = new com.ebsco.platform.Shared()

  // Ensure we start with an empty directory.
  deleteDir()

    def pythonDir = "python"
    def pythonCmd = ". $pythonDir/bin/activate; python"
    def pylintCmd = ". $pythonDir/bin/activate; pylint"
    def pipCmd    = ". $pythonDir/bin/activate; pip"

    sh "virtualenv $pythonDir"
    sh "$pipCmd install pylint"
    sh "$pipCmd install wheel"

  // Checkout the repo from github
  stage ('checkout') {
    checkout scm

  }

  stage("Test") {
    sh "$pythonCmd setup.py test"
  }

  stage("Package") {
    sh "$pythonCmd setup.py bdist_wheel --universal"
  }

 /*
  * Publish to file share or pypi
  */

}
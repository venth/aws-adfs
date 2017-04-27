#!groovy
@Library("platform.infrastructure.jenkinslib")
import com.ebsco.platform.Shared

node("docker") {

  // Create a groovy library object from the Shared.groovy file.
  def shared = new com.ebsco.platform.Shared()

  // Ensure we start with an empty directory.
  deleteDir()

  // Checkout the repo from github
  stage ('checkout') {
    checkout scm
  }

  stage("Test") {
    sh "python setup.py test"
  }

  stage("Package") {
    sh "python setup.py bdist_wheel --universal"
  }

 /*
  * Publish to file share or pypi
  */

}
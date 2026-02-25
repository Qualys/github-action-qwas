@Library("jenkins-libraries-v2@master")
import com.qualys.pipeline.*

def templateName = "generic-docker-template"
def branch = "master"
def nodeLabel = "slave"

pipeline = loadPipelineTemplate(templateName, branch, nodeLabel)

def customPreHookStep = {sh "sed -i 's/<release.number>RELEASE<\\/release.number>/<release.number>${BUILD_ID}<\\/release.number>/g' ${WORKSPACE}/pom.xml"}

HooksHelper hook = new HooksHelper()
hook.addPreHook(StageName.BUILD, customPreHookStep)

// use when hook is enabled
pipeline.runPipeline("properties.yaml", nodeLabel, hook)

//pipeline.runPipeline("properties.yaml", nodeLabel)

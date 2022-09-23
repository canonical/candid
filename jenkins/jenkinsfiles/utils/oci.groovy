// Containers OCI related commands
// for the build process.

/**
 * Builds the dockerfile frontendv/0 compliant image. 
 */
/* groovylint-disable-next-line BuilderMethodWithSideEffects, FactoryMethodName */
void buildImage(String target) {
//            --build-arg http_proxy=${env.HTTP_PROXY} \
//            --build-arg https_proxy=${env.HTTPS_PROXY} \
    sh """
        docker build \
            --secret id=ghuser,env=GITHUB_PAT_AUTH_USR \
            --secret id=ghpat,env=GITHUB_PAT_AUTH_PSW \
            . -f ./Dockerfile -t ${target}
    """
}


void saveImage(String target) {
    sh """
        docker save ${target} | gzip > ${target.split(':')[0]}-image.tar.gz
    """
}



/**
 * Scans an image using trivy.
 */
void scanImage(String target) {
    // # --build-arg http_proxy=${env.HTTP_PROXY} \
    // # --build-arg https_proxy=${env.HTTPS_PROXY} \
    sh """
        docker run \
            --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v ${env.JENKINS_HOME}/trivy-cache/${env.JOB_NAME}/Library/Caches:/root/.cache/ \
            aquasec/trivy:0.31.3 image ${target}
    """
}

/* groovylint-disable-next-line CompileStatic */
return this

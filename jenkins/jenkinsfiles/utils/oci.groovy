// Containers OCI related commands
// for the build process.

/**
 * Builds the dockerfile frontendv/0 compliant image. 
 */
/* groovylint-disable-next-line BuilderMethodWithSideEffects, FactoryMethodName */
void buildImage() {
    sh """
        docker build \
            --build-arg http_proxy=${params.http_proxy} \
            --build-arg https_proxy=${params.http_proxy} \
            --secret id=ghuser,env=GITHUB_PAT_AUTH_USR \
            --secret id=ghpat,env=GITHUB_PAT_AUTH_PSW \
            . -f ./docker/Dockerfile -t candid:latest
    """
}

/**
 * Scans an image using trivvy.
 */
void scanImage() {
    sh """
        docker run \
            --env HTTP_PROXY=${params.http_proxy} \
            --env HTTPS_PROXY=${params.http_proxy} \
            --rm \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v $HOME/Library/Caches:/root/.cache/ \
            aquasec/trivy:0.31.3 image candid:latest
    """
}

/* groovylint-disable-next-line CompileStatic */
return this

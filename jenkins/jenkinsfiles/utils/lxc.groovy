/* groovylint-disable CompileStatic, LineLength */
void launchContainer(String release) {
    sh """
        sudo -u ${env.LXC_USER} -H -E -- lxc launch --ephemeral ${release} ${env.BUILD_TAG}
    """
    s('while [ ! -f /var/lib/cloud/instance/boot-finished ]; do sleep 0.1; done')
}

void pushWorkspace() {
    echo 'pushing workspace'
    sh """
        sudo -u ${env.LXC_USER} -H -E -- lxc exec --cwd /home/ubuntu/${env.JOB_BASE_NAME} --user 1000 --group 1000 --env HOME=/home/ubuntu --env HTTP_PROXY==${env.HTTP_PROXY} --env HTTPS_PROXY=${env.HTTPS_PROXY} ${env.BUILD_TAG}  -- mkdir -p  /home/ubuntu/${env.JOB_BASE_NAME}
        tar c . | sudo -u ${env.LXC_USER} -H -E -- lxc exec --cwd /home/ubuntu/${env.JOB_BASE_NAME} --user 1000 --group 1000 --env HOME=/home/ubuntu --env HTTP_PROXY==${env.HTTP_PROXY} --env HTTPS_PROXY=${env.HTTPS_PROXY} ${env.BUILD_TAG}  -- tar x
    """
    echo 'done'
    // s('ls -lah')
    // Can't use --uid/--gid/--mode in lxc file push recursive mode
    // So we just chown it after the fact.
    // s('sudo chown -R ubuntu:root ./')
}

//
void pullFileFromHome(String path) {
    cmd =  "lxc file pull ${env.BUILD_TAG}/home/ubuntu/${path} ." 
}

void s(String command, List<String> envArgs=[]) {
    String cmd = "sudo -u ${env.LXC_USER} -H -E -- lxc exec ${env.BUILD_TAG} --cwd /home/ubuntu/${env.JOB_BASE_NAME} --user 1000 --env HOME=/home/ubuntu --env HTTP_PROXY==${env.HTTP_PROXY} --env HTTPS_PROXY=${env.HTTPS_PROXY} --env http_proxy=${env.HTTP_PROXY} --env https_proxy=${env.HTTPS_PROXY} " 
    envArgs.each { env -> cmd <<= (' --env ' + env + ' ') }
    cmd <<= ' -- bash -c '
    cmd <<= "\'${command.trim()}\'"
    echo "${cmd}"
    sh(script: "${cmd}")
}

void installSnap(String name, Boolean classic=false, String channel='') {
    String cmd = 'sudo snap install '
    cmd <<= name
    if (classic) {
        cmd <<= ' --classic'
    }
    if (channel != '') {
        cmd <<= " --channel=${channel}"
    }
    s(cmd)
}

void removeContainer() {
    sh '''
        sudo -u $LXC_USER -H -E -- lxc delete $BUILD_TAG --force
    '''
}

return this

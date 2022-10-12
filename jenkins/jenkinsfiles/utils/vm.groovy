// We want to control the snap build environment
// as such we don't allow the default configuration
// of snapcraft to create the VM for us, but rather
// create the VMs by name explicitly and remove explicitly.
//
// This little lib creates VMs named with the current
// BUILD_TAG.

/**
 * Launches a multipass VM named by BUILD_TAG.
 * TODO: We're using base mem and cpu, --cpus 4 --mem 8G would be ideal.
 * But we don't have the resources yet.
 */
void launchVM() {
    sh """
        sudo -u $VM_USER -- multipass launch 20.04 --name $BUILD_TAG
    """
}

/**
 * Cleans up the multipass VM by BUILD_TAG
 * and then purges.
 */
void cleanupVM() {
    sh """
        sudo -u $VM_USER -- multipass delete $BUILD_TAG
        sudo -u $VM_USER -- multipass purge
    """
}

/**
 * Mounts the workspace into the project under ./proj
 */
void mountWorkspaceIntoProj() {
    // Execs will now default to ./proj
    sh "sudo -u $VM_USER -- multipass mount -u 1000:1000 -g 1000:1000 ./ $BUILD_TAG:./proj"
}

/**
 * Wraps the sh step with:
 * - The $VM_USER user.
 * - Linux proxy set to params provided.
 * - Executes against the VM named by BUILD_TAG.
 */
void s(String command) {
    export http_proxy=${params.http_proxy}s; \
    export https_proxy=${params.http_proxy}; \s
    sh """
        sudo -u $VM_USER -- multipass exec ${env.BUILD_TAG} \
            -- bash -c '${command.trim()}'
    """
}

/**
 * Installs a snap into the VM
 */
void installSnap(String name, Boolean classic=false, String channel='') {
    String cmd = 'sudo snap install '
    cmd <<= name
    if (classic) {
        cmd <<= ' --classic '
    }
    if (channel != '') {
        cmd <<= "--channel=${channel}"
    }
    s(cmd)
}

/* groovylint-disable-next-line CompileStatic */
return this

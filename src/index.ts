import * as core from '@actions/core'
import * as github from '@actions/github'

/** Retrieves and outputs the github PR title
 * @returns void
 * */
const run = async (): Promise<void> => {
    try {
        const prtitle = github.context.payload.pull_request?.title
        core.setOutput('pr-title', prtitle)
    } catch (error) {
        core.setFailed((error as Error).message)
    }
}

run()

const assert = require('assert')
const http = require('http')
const https = require('https')
const url = require('url')
const crypto = require('crypto')
const zlib = require('zlib')

let headers = {"accept":"application/json", "x-detectify-key":process.env.DETECTIFY_TOKEN, "accept-encoding":"gzip"}

function sign(method, uri, payload) {
	let hmac = crypto.createHmac("sha256", Buffer.from(process.env.DETECTIFY_SECRET_TOKEN, 'base64'))
	let now = Math.round(Date.now() / 1000).toString()
	if(!payload) {
		payload = ""
	}
	if(typeof(payload) !== 'string') {
		payload = JSON.stringify(payload)
	}
	let path = url.parse(uri).pathname
	if(path.startsWith("/rest/")) {
		path = path.substring(5)
	}
	let tosign = method.toUpperCase() + ";" + path + ";" + process.env.DETECTIFY_TOKEN + ";" + now + ";" + payload
	if(process.env.DEBUG) console.log('signing', tosign)
	hmac.update(tosign)
	return {'x-detectify-signature':hmac.digest('base64'), 'x-detectify-timestamp':now}
}

function request(method, uri, headers, payload) {
	return new Promise((resolve, reject) => {
		let proto = uri.startsWith("http://") ? http : https
		headers = Object.assign(headers, sign(method, uri, payload))
		if(payload) {
			payload = typeof(payload) === 'string' ? payload : JSON.stringify(payload)
			headers = Object.assign(headers, {"content-type":"application/json", "content-length":payload.length.toString()})
		}
		if(process.env.DEBUG) console.log('request', Object.assign(url.parse(uri), {headers, method}))
		let req = proto.request(Object.assign(url.parse(uri), {headers, method}), (res) => {
			let data = Buffer.alloc(0)
			res.on('data', (chunk) => data = Buffer.concat([data, chunk]))
			res.on('end', () => {
				if(process.env.DEBUG) console.log('response', res.headers, res.statusCode, res.statusMessage)
				if(res.statusCode === 202) {
					return resolve({})
				}
				if(res.statusCode > 399 || res.statusCode < 200) {
					return reject(new Error('Unable to complete request, status code response was ' + res.statusCode + ' ' + res.statusMessage))
				} else {
					if(res.headers['content-encoding'] === 'gzip') {
						data = zlib.gunzipSync(data)
					}
					if(process.env.DEBUG) console.log('response data', data.toString('utf8'))
					return resolve(JSON.parse(data.toString('utf8')))
				}
			})
		})
		req.on('error', (e) => reject(e))
		if(payload) {
			req.write(payload)
		}
		req.end()
	})
}

function wait(timeinmill) {
	return new Promise((resolve, reject) => setTimeout(() => resolve(), timeinmill))
}

async function scan_domain(domain) {
	let domains = await request("get", "https://api.detectify.com/rest/v2/domains/", headers, null)
	domains = domains.filter((x) => domain.indexOf(x.name) > -1)
	assert.ok(domains.length > 0, 'The domain could not be found, even though, it should have been.')
	let domain_token = domains[0].token

	assert.ok(domain_token, 'The domain token was null or undefined.')

	let scan_profiles = await request("get", `https://api.detectify.com/rest/v2/profiles/${domain_token}/`, headers, null)
	let profile_token = null

	if(scan_profiles.filter(x => x.name === domain).length === 0) {
		create_profile = await request("post", "https://api.detectify.com/rest/v2/profiles/", headers, {"domain_token":domain_token, "name":domain, "endpoint":domain,  "unique":true, "valid":true})
		profile_token = create_profile.token
		scan_profiles = scan_profiles.concat([create_profile])
	} else {
		scan_profiles = scan_profiles.filter(x => x.name === domain)
		profile_token = scan_profiles[0].token
	}

	assert.ok(profile_token, 'The profile token was null or undefined.')

	for(let i=0; i < 20 && scan_profiles[0].status !== 'verified'; i++) {
		scan_profiles = await request("get", `https://api.detectify.com/rest/v2/profiles/${domain_token}/`, headers, null)
		scan_profiles = scan_profiles.filter(x => x.name === domain)
		if(scan_profiles[0].status !== 'verified' && scan_profiles[0].status !== 'unverified') {
			throw new Error(`Error fetching scan profile ${JSON.stringify(scan_profiles[0])}`)
		}
		await wait(5000)
	}


	let scan_status = await request("get", `https://api.detectify.com/rest/v2/scans/${profile_token}/`, headers, null)
	if(scan_status.state !== 'starting' && scan_status.state !== 'running' && scan_status.state !== 'stopping') {
		scan_status = await request("post", `https://api.detectify.com/rest/v2/scans/${profile_token}/`, headers, null)
		scan_status = await request("get", `https://api.detectify.com/rest/v2/scans/${profile_token}/`, headers, null)
	}

	for(let i=0; i < 20 && scan_status.state != "stopped"; i++) {
		scan_status = await request("get", `https://api.detectify.com/rest/v2/scans/${profile_token}/`, headers, null)
		if (scan_status.state !== "starting" && scan_status.state !== "running" && scan_status.state !== "stopping" && scan_status.state !== "stopped") {
			throw new Error(`Error fetching scan status: ${scan_status.state}`)
		}
		await wait(5000)
	}

	return await request("get", `https://api.detectify.com/rest/v2/fullreports/${profile_token}/latest/`, headers, null)
}

if (require.main === module) {
	assert.ok(process.argv[2], 'No domain name was passed in.')
	scan_domain(process.argv[2])
		.then((result) => console.log(JSON.stringify(result, null, 2)))
		.catch((err) => console.error(err))
} else {
	module.exports = {scan_domain}
}
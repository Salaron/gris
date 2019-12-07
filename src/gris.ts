import crypto from "crypto"
import createDebug from "debug"
import querystring from "querystring"
import request from "superagent"
import { aes128cbcEncrypt, hmacSha1, xor } from "./util/crypto"
import { getRandomNumber, sleep, timeStamp } from "./util/helpers"
// tslint:disable-next-line: no-var-requires
const uuid = require("uuid/v4")
const debug = createDebug("gris")

export enum gameMode {
  MUSE = 1,
  AQOURS = 2,
}

export enum platformType {
  iOS = 1,
  Android = 2,
}

// Those values for JP
// for unknown reason iOS client using https protocol while Android client using http
const defaultHost = "https://prod-jp.lovelive.ge.klabgames.net"
const defaultApplicationId = 626776655    // application ID in iTunes
const defaultPlatform: platformType = platformType.iOS
const defaultOsVersion = "iPhone10_1 iPhone 11.3"
const defaultClientVersion = "41.4"
const defaultBundleVersion = "6.9.1"
const defaultNames = [
  "真面目な学院生", "明るい学院生", "心優しい学院生", "アイドル好きの学院生", "期待の学院生", "頼りになる学院生",
  "素直な学院生", "さすらいの学院生", "気になる学院生", "憧れの学院生", "元気な学院生", "勇敢な学院生", "さわやかな学院生",
  "幻の学院生", "天然な学院生", "癒し系な学院生", "純粋な学院生", "正義感あふれる学院生", "カラオケ好きの学院生", "不思議な学院生",
]

export interface IConfig {
  host?: string
  gameMode?: gameMode
  platformType?: platformType
  applicationId?: number
  bundleVersion?: string
  clientVersion?: string
  // tslint:disable-next-line: max-line-length
  osVersion?: string // values from build.prop: ro.product.model, ro.product.brand, ro.product.board, ro.build.version.release for Android
  loginKey?: string
  loginPasswd?: string

  publicKey: string
  baseKey: string
  applicationKey: string
}

export interface ISession {
  authToken: string
  userId: number
  mgd: gameMode
  nonce: number
  commandNum: number
  bundleVersion: string
  clientVersion: string
}

export interface IKeychain {
  rsaPublicKey: string
  applicationKey: string
  baseKey: string
  loginKey: string
  loginPasswd: string
  sessionKey: Buffer
}

export interface IAuthorize {
  consumerKey: string
  timeStamp: number
  version: "1.1"
  nonce: number
  token?: string
}

export interface IServerResponse<T extends any> {
  response_data: T
  release_info: Array<{
    id: number
    key: string
  }>
  status_code: number
}

export interface IAPIRequestOptions {
  excludeDefaultValues?: boolean
  useSpecialKey?: boolean
}

export class Gris {

  public get gameMode() {
    return this.session.mgd
  }
  public set gameMode(mode: gameMode) {
    this.session.mgd = mode
  }

  /**
   * Generate random login key and login passwd pair
   */
  public static generateCredentials() {
    return [uuid(), crypto.createHash("sha512").update([uuid(), Date.now()].toString()).digest("hex")]
  }

  public session: ISession = {
    authToken: "",
    userId: 0,
    nonce: 0,
    commandNum: 2, // not same as nonce. increment only if it was in requestData and request was successful
    mgd: gameMode.AQOURS,
    bundleVersion: defaultBundleVersion,
    clientVersion: defaultClientVersion,
  }
  public keychain: IKeychain = {
    rsaPublicKey: "",
    applicationKey: "",
    baseKey: "",
    loginKey: "",
    loginPasswd: "",
    sessionKey: Buffer.alloc(32),
  }

  private HOST = defaultHost
  private osVersion = defaultOsVersion
  private platformType = defaultPlatform
  private applicationId = defaultApplicationId
  constructor(options: IConfig) {
    if (
      options.loginKey?.length === 36 &&
      options.loginKey?.match(/^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/gi)
    ) {
      this.keychain.loginKey = options.loginKey
    }
    if (options.loginPasswd?.length === 128 && options.loginPasswd?.match(/^[0-9A-Z]{128}/gi)) {
      this.keychain.loginPasswd = options.loginPasswd
    }

    if (options.baseKey.length !== 32 || options.applicationKey.length !== 32) {
      throw new Error(`Application key or base key have invalid format`)
    }

    if (options.publicKey.length === 0 || options.publicKey.length < 250) {
      throw new Error(`Public key is missing or have invalid format`)
    }

    this.keychain.rsaPublicKey = options.publicKey
    this.keychain.applicationKey = options.applicationKey
    this.keychain.baseKey = options.baseKey

    if (options.host) {
      if (!options.host.includes("://")) throw new Error(`protocol is not specified`)
      this.HOST = options.host
    }

    if (options.applicationId) {
      this.applicationId = options.applicationId
    }
    if (options.platformType) {
      this.platformType = options.platformType
    }
    if (options.osVersion) {
      this.osVersion = options.osVersion
    }

    if (options.gameMode) {
      this.session.mgd = options.gameMode
    }
  }

  /**
   * Register new account on the server
   */
  public async register(options: {
    name?: string,
    loginKey?: string,
    loginPasswd?: string
  } = {}) {
    this.session.bundleVersion = await this.getLatestBundleVersion()

    if (typeof options.loginKey !== "string" || typeof options.loginPasswd !== "string") {
      // generate new credentials if not specifiend
      const [loginKey, loginPasswd] = Gris.generateCredentials()
      options.loginKey = loginKey
      options.loginPasswd = loginPasswd
    }
    this.keychain.loginKey = options.loginKey!
    this.keychain.loginPasswd = options.loginPasswd!
    if (typeof options.name !== "string") {
      // select random name
      options.name = defaultNames[Math.floor(Math.random() * defaultNames.length)]
    }
    await this.doAuth()
    const startUpRequestData = {
      login_key: aes128cbcEncrypt(
        this.keychain.loginKey,
        this.keychain.sessionKey.slice(0, 16),
        this.keychain.sessionKey.slice(16, 32)
      ),
      login_passwd: aes128cbcEncrypt(
        this.keychain.loginPasswd,
        this.keychain.sessionKey.slice(0, 16),
        this.keychain.sessionKey.slice(16, 32)
      ),
    }
    const startUpResponseData = await this.APIRequest("login/startUp", startUpRequestData, {
      excludeDefaultValues: true,
    })
    debug(`Registered new account #${startUpResponseData.response_data.user_id}`)
    await this.login()

    await this.APIRequest("user/userInfo")
    const tos = await this.APIRequest("tos/tosCheck")

    if (tos.response_data.is_agreed === false) {
      debug("Agreeing to TOS...")
      await sleep(getRandomNumber(1, 3) * 1000)
      await this.APIRequest("tos/tosAgree", {
        tos_id: tos.response_data.tos_id,
      })
    }

    await this.APIRequest("user/changeName", {
      name: options.name,
    })
    await this.APIRequest("tutorial/progress", {
      tutorial_state: 1,
    })
    await this.startupMultiRequest()

    const unitListResponseData = await this.APIRequest("login/unitList")
    debug("Selecting leader...")
    const leaders = [
      ...unitListResponseData.response_data.member_category_list[0].unit_initial_set,
      ...unitListResponseData.response_data.member_category_list[1].unit_initial_set,
    ]

    await sleep(getRandomNumber(1, 3) * 1000)
    const selectedLeader = leaders[Math.floor(Math.random() * leaders.length)].unit_initial_set_id
    if (leaders.indexOf(selectedLeader) > 8) {
      this.gameMode = gameMode.AQOURS
    } else {
      this.gameMode = gameMode.MUSE
    }
    debug(`We're choose set id #${selectedLeader}`)
    await this.APIRequest("login/unitSelect", {
      unit_initial_set_id: selectedLeader,
    })

    await this.APIRequest("tutorial/skip")

    const unit = await this.APIMultiRequest([
      { module: "unit", action: "unitAll" },
      { module: "unit", action: "deckInfo" },
      { module: "unit", action: "supporterAll" },
    ])
    await this.APIRequest("unit/merge", {
      unit_owning_user_ids: [unit.response_data[0].result.active[10].unit_owning_user_id],
      base_owning_unit_user_id: unit.response_data[0].result.active[0].unit_owning_user_id,
      unit_support_list: [],
    })

    await this.APIRequest("tutorial/skip")
    await this.APIRequest("unit/rankUp", {
      unit_owning_user_ids: [unit.response_data[0].result.active[9].unit_owning_user_id],
      base_owning_unit_user_id: unit.response_data[0].result.active[0].unit_owning_user_id,
    })

    await this.APIRequest("tutorial/skip")

    const userInfo = await this.APIRequest("user/userInfo")
    await this.APIRequest("personalnotice/get")
    await this.APIRequest("lbonus/execute")
    await this.startupMultiRequest()
    return {
      userInfo: userInfo.response_data.user,
      loginKey: options.loginKey,
      loginPasswd: options.loginPasswd,
    }
  }

  /**
   *  Emulate application client launch.
   */
  public async startApp() {
    await this.login()
    const userInfo = await this.APIRequest("user/userInfo")
    const notice = await this.APIRequest("personalnotice/get")
    await this.APIRequest("tos/tosCheck")
    const kidStatus = await this.APIRequest("handover/kidStatus")
    await this.APIRequest("download/event", {
      client_version: this.session.clientVersion.toString(),
      os: this.getPlatformString(),
      package_type: 5,
      excluded_package_ids: [],
      commandNum: null,
    }, {
      excludeDefaultValues: true,
    })
    await this.APIRequest("lbonus/execute")
    await this.startupMultiRequest()
    return [userInfo, notice, kidStatus]
  }

  /**
   * Emulate login.
   *
   * After calling this method you can access to API
   */
  public async login(): Promise<number> {
    if (
      this.keychain.loginKey.length !== 36 ||
      !this.keychain.loginKey.match(/^[0-9A-F]{8}-[0-9A-F]{4}-4[0-9A-F]{3}-[89AB][0-9A-F]{3}-[0-9A-F]{12}$/gi)
    ) throw new Error(`login key is not specified or it have invalid format`)
    if (
      this.keychain.loginPasswd.length !== 128 ||
      !this.keychain.loginPasswd.match(/^[0-9A-Z]{128}/gi)
    ) throw new Error(`login passwd is not specified or it have invalid format`)

    this.session.bundleVersion = await this.getLatestBundleVersion()

    await this.doAuth()
    const loginRequestData = {
      login_key: aes128cbcEncrypt(
        this.keychain.loginKey,
        this.keychain.sessionKey.slice(0, 16),
        this.keychain.sessionKey.slice(16, 32)
      ),
      login_passwd: aes128cbcEncrypt(
        this.keychain.loginPasswd,
        this.keychain.sessionKey.slice(0, 16),
        this.keychain.sessionKey.slice(16, 32)
      ),
    }
    const loginResponseData = await this.APIRequest("login/login", loginRequestData, {
      excludeDefaultValues: true,
    })

    this.session.userId = loginResponseData.response_data.user_id
    this.session.authToken = loginResponseData.response_data.authorize_token
    return this.session.userId
  }

  /**
   * Execute API request.
   * @param endPoint module/action endpoint. Example: ``user/userInfo``
   */
  public async APIRequest(endPoint: string, requestData: any = {}, options: IAPIRequestOptions = {}) {
    debug(`Submiting single API request to "${endPoint}"`)

    let signKey = this.keychain.sessionKey
    if (options.useSpecialKey) {
      signKey = Buffer.concat([
        xor(this.keychain.applicationKey.slice(0, 16), this.keychain.baseKey.slice(16, 32)),
        xor(this.keychain.applicationKey.slice(16, 32), this.keychain.baseKey.slice(0, 16)),
      ])
    }

    if ("timeStamp" in requestData) requestData.timeStamp = timeStamp()
    if ("mgd" in requestData) requestData.mgd = this.gameMode
    if ("commandNum" in requestData) requestData.commandNum = `${this.keychain.loginKey}.${timeStamp()}.${this.session.commandNum}`
    if (!options.excludeDefaultValues) {
      const endPointSplit = endPoint.split("/")
      requestData.module = endPointSplit[0]
      requestData.action = endPointSplit[1]
      requestData.timeStamp = timeStamp()
      requestData.mgd = this.gameMode
      requestData.commandNum = `${this.keychain.loginKey}.${timeStamp()}.${this.session.commandNum}`
    }
    const response = await this.postRequest(endPoint, signKey, requestData)

    if (requestData?.commandNum) this.session.commandNum += 1

    return response
  }

  /**
   * Execute more than one methods in single request.
   */
  public async APIMultiRequest(methods: Array<{ module: string, action: string, [key: string]: string | number }>) {
    debug(`Submiting multi API request`)
    const response = await this.postRequest("api", this.keychain.sessionKey, methods.map((method) => {
      method.timeStamp = timeStamp()
      return method
    }))

    return response
  }

  public async startupMultiRequest() {
    await this.APIMultiRequest([
      { module: "login", action: "topInfo" },
      { module: "login", action: "topInfoOnce" },
      { module: "live", action: "liveStatus" },
      { module: "live", action: "schedule" },
      { module: "marathon", action: "marathonInfo" },
      { module: "battle", action: "battleInfo" },
      { module: "festival", action: "festivalInfo" },
      { module: "online", action: "info" },
      { module: "challenge", action: "challengeInfo" },
      { module: "quest", action: "questInfo" },
      { module: "duty", action: "dutyInfo" },
      { module: "unit", action: "unitAll" },
      { module: "unit", action: "deckInfo" },
      { module: "unit", action: "supporterAll" },
      { module: "unit", action: "removableSkillInfo" },
      { module: "album", action: "albumAll" },
      { module: "scenario", action: "scenarioStatus" },
      { module: "subscenario", action: "subscenarioStatus" },
      { module: "eventscenario", action: "status" },
      { module: "multiunit", action: "multiunitscenarioStatus" },
      { module: "payment", action: "productList" },
      { module: "banner", action: "bannerList" },
      { module: "notice", action: "noticeMarquee" },
      { module: "user", action: "getNavi" },
      { module: "navigation", action: "specialCutin" },
      { module: "award", action: "awardInfo" },
      { module: "background", action: "backgroundInfo" },
      { module: "stamp", action: "stampInfo" },
      { module: "exchange", action: "owningPoint" },
      { module: "livese", action: "liveseInfo" },
      { module: "liveicon", action: "liveiconInfo" },
      { module: "item", action: "list" },
    ])
  }

  /**
   * Get latest version of application from iTunes
   * @param applicationId Application ID
   * @returns {string} Latest version of app in iTunes
   */
  public async getLatestBundleVersion(applicationId?: number | string): Promise<string> {
    if (!applicationId) applicationId = this.applicationId
    const url = `https://itunes.apple.com/lookup?id=${applicationId}&lang=ja_jp&country=jp&rnd=${getRandomNumber(10000000, 99999999)}`
    const response = await request.get(url)
    return JSON.parse(response.text).results[0].version
  }

  public getHeaders() {
    return <{ [header: string]: string }>{
      "Accept": "*/*",
      "API-Model": "straightforward",
      "Debug": "1",
      "Bundle-Version": this.session.bundleVersion,
      "Client-Version": this.session.clientVersion,
      "OS-Version": this.osVersion,
      "OS": this.getPlatformString(),
      "Platform-Type": this.platformType.toString(),
      "Application-ID": this.applicationId.toString(),
      "Time-Zone": "JST",
      "Region": "392",
      "X-BUNDLE-ID": "klb.android.lovelive",
    }
  }

  public getPlatformString() {
    return this.platformType === platformType.iOS ? "iOS" : "Android"
  }

  /**
   * Returns Authorize header
   */
  protected getAuthorizeString(): string {
    const authorize: IAuthorize = {
      consumerKey: "lovelive_test",
      timeStamp: timeStamp(),
      version: "1.1",
      nonce: this.session.nonce,
    }
    if (this.session.authToken.length > 0) {
      authorize.token = this.session.authToken
    }
    return querystring.stringify(<any>authorize)
  }

  /**
   * Make POST request to server using superagent
   */
  protected async postRequest(endPoint: string, signKey: Buffer, formData?: any) {
    // tslint:disable-next-line: prefer-const
    let [contentType, requestBody] = this.createMultipart(JSON.stringify(formData))
    const headers = this.getHeaders()
    if (typeof formData !== "undefined") {
      headers["X-Message-Code"] = hmacSha1(JSON.stringify(formData), signKey)
      headers["Content-Length"] = requestBody.length.toString()
      headers["Content-Type"] = contentType
    }

    if (this.session.userId) {
      headers["User-ID"] = this.session.userId.toString()
    }

    let response: request.Response | undefined
    for (let attempt = 1; attempt <= 5; attempt++) {
      // increment nonce after every request
      this.session.nonce += 1
      headers.Authorize = this.getAuthorizeString()
      try {
        if (typeof formData !== "undefined") {
          response = await request.post(`${this.HOST}/main.php/${endPoint}`).set(headers).send(requestBody)
        } else {
          response = await request.post(`${this.HOST}/main.php/${endPoint}`).set(headers)
        }
      } catch (err) {
        if (err.status === 423) throw new Error(`This account is locked a.k.a. banned`)
        if (attempt === 5) throw new Error(`Maximum reconnecting attempts reached.\n${err.message}`)
        debug(err)
        await sleep(3000)
        continue
      }
      if (response && response.header.maintenance) throw new Error(`The server is under maintenance`)

      if (
        response &&
        response.header["server-version"] &&
        response.header["server-version"] !== this.session.clientVersion &&
        !endPoint.includes("login")
      ) {
        // Resend request after version changing
        this.session.clientVersion = response.header["server-version"]
        // Also increment nonce
        this.session.nonce += 1
        debug("Sleeping for a bit after version changing")
        // wait for 1 sec
        await sleep(1000)
        continue
      }
      break
    }
    if (!response) throw new Error(`Unable to connect to server`)
    // TODO: typeliteral?
    // TODO: error codes handling
    const responseBody: IServerResponse<any> = JSON.parse(response.text)
    if (responseBody.response_data.error_code === 407) throw new Error(`wrong credentials`)
    if (!responseBody.response_data)
      throw new Error(`Invalid response: response_data is missing\nRaw: ${response.text}`)
    return responseBody
  }

  private async doAuth(): Promise<void> {
    if (
      typeof this.keychain.loginKey !== "string" ||
      typeof this.keychain.loginPasswd !== "string"
    ) throw new Error(`login key and login passwd required to pass auth stage ._.`)

    const clientKey = crypto.randomBytes(32)
    this.keychain.sessionKey = xor(xor(this.keychain.applicationKey, this.keychain.baseKey), clientKey)
    const authKeyRequestData = {
      auth_data: aes128cbcEncrypt(JSON.stringify({
        1: this.keychain.loginKey,
        2: this.keychain.loginPasswd,
        3: this.getAssertation(),
      }), clientKey.slice(0, 16), clientKey.slice(16, 32)),
      dummy_token: crypto.publicEncrypt({
        key: this.keychain.rsaPublicKey,
        padding: crypto.constants.RSA_PKCS1_PADDING,
      }, clientKey).toString("base64"),
    }

    const authKeyResponseData = await this.APIRequest("login/authkey", authKeyRequestData, {
      excludeDefaultValues: true,
    })
    this.session.authToken = authKeyResponseData.response_data.authorize_token
    this.keychain.sessionKey = xor(clientKey, Buffer.from(authKeyResponseData.response_data.dummy_token, "base64"))
  }

  /**
   * Creates SIF like multipart.
   *
   * @param requestBody content that we want to send to the server
   *
   * @returns [contentType, body]
   */
  private createMultipart(requestBody: string): [string, string] {
    // generate random 16 chars for boundary
    const boundary = "-".repeat(24) + crypto.randomBytes(8).toString("hex")
    const body = `--${boundary}\r\nContent-Disposition: form-data; name="request_data"\r\n\r\n${requestBody}\r\n--${boundary}--\r\n`
    const contentType = `multipart/form-data; boundary=${boundary}`
    return [contentType, body]
  }

  private getAssertation() {
    switch (this.platformType) {
      case platformType.iOS: {
        return "ewoJIlJhdGluZyI6IjAiLAoJIkRldGFpbCI6IlRoaXMgaXMgYSBpT1MgZGV2aWNlIgp9"
      }
      case platformType.Android: {
        throw new Error("TODO?")
      }
      default: {
        throw new Error("Unimplemented")
      }
    }
  }
}

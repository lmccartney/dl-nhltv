import getpass
import http.cookiejar
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.error
import urllib.parse
import urllib.parse
import urllib.request
import urllib.request
from datetime import (
    datetime,
    timedelta,
)
from urllib.error import HTTPError

from nhltv_lib.common import (
    COOKIES_LWP_FILE,
    COOKIES_TXT_FILE,
    getSetting,
    MASTER_FILE_TYPE,
    setSetting,
    tprint,
    UA_NHL,
    UA_PC,
    UA_PS4,
    wait,
)


class BlackoutRestriction(Exception):
    """Tried to download Blackout Restricted game! """
    pass


class NoGameFound(Exception):
    """When checking for the next game we could not find one """
    pass


class GameStartedButNotAvailableYet(Exception):
    """
    When checking for the next game we found one but is not available for
    download yet
     """
    pass


def remove_lines_without_errors(errors):
    # Open download file
    download_file = open("./temp/download_file.txt", "r+")
    download_file_lines = download_file.readlines()

    download_file.seek(0)
    write_next = False
    for line in download_file_lines:
        for error in errors:
            # For each error check to see if it is in the line
            # If it is then write that line and the next one
            if error in line:
                download_file.write(line)
                write_next = True
            if write_next and 'out=temp/' in line:
                download_file.write(line)
                write_next = False
    download_file.truncate()
    download_file.close()


def redo_broken_downloads(out_file):
    log_file_name = f'{out_file}_download.log'

    # Set counters
    last_error_count = 0
    last_line_number = 0

    while True:
        # Loop through log file looking for errors
        log_file = open(log_file_name, "r")
        errors = []
        cur_line_number = 0
        for line in log_file:
            cur_line_number = cur_line_number + 1
            if cur_line_number > last_line_number:
                # Is line an error?
                if '[ERROR]' in line:
                    error_match = re.search(
                        r'/.*K/(.*)',
                        line,
                        re.M | re.I
                    ).group(1)
                    errors.append(error_match)
        last_line_number = cur_line_number
        log_file.close()

        if len(errors) > 0:
            tprint('Found ' + str(len(errors)) + ' download errors.')
            if last_error_count == len(errors):
                reason = "Same number of errors as last time so waiting 10 " \
                         "minutes"
                wait(reason=reason, minutes=10)
            remove_lines_without_errors(errors)

            tprint('Trying to download the erroneous files again...')

            # User aria2 to download the list
            command = [
                'aria2c',
                '-i',
                './temp/download_file.txt',
                '-j=20',
                f'--load - cookies = {COOKIES_TXT_FILE}',
                f'--log="{log_file_name}"',
                '--log-level=notice',
                '--quiet=true',
                '--retry-wait=1',
                '--max-file-not-found=5',
                '--max-tries=5',
                '--header="Accept: */*"',
                '--header = "Accept-Language: en-US,en;q=0.8"',
                '--header="Origin: https://www.nhl.com"',
                '-U="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 '
                '(KHTML, ',
                'like Gecko) Chrome/48.0.2564.97 Safari/537.36"',
                '--enable-http-pipelining=true',
                '--auto-file-renaming=false',
                '--allow-overwrite=true',
            ]
            _ = subprocess.Popen(command, stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT,
                                 shell=True).wait()

            last_error_count = len(errors)


class DownloadNHL(object):
    quality = "5000"
    retry_errored_downloads = False
    userName = ""
    passWord = ""
    teamID = 0
    BlackoutRestriction = BlackoutRestriction
    NoGameFound = NoGameFound
    GameStartedButNotAvailableYet = GameStartedButNotAvailableYet

    def get_quality_url_from_master(self, master_file):
        # Parse the master and get the quality URL
        fh = open(master_file, 'r')
        return_line = None
        for line in fh:
            return_line = line
            if self.quality + 'K' in return_line:
                return return_line

        # Otherwise we return the highest value
        return return_line

    @staticmethod
    def download_web_page(url, output_file, log_file):
        command = [
            'aria2c',
            f'-o={output_file}',
            f'--load-cookies={COOKIES_TXT_FILE}',
            f'--log="{log_file}"',
            '--log-level=notice',
            '--quiet=true',
            '--retry-wait=1',
            '--max-file-not-found=5',
            '--max-tries=5',
            '--header="Accept: */*"',
            '--header="Accept-Language: en-US,en;q=0.8"',
            '--header="Origin: https://www.nhl.com"',
            '-U="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 ('
            'KHTML, like Gecko) Chrome/48.0.2564.97 Safari/537.36"',
            '--enable-http-pipelining=true',
            '--auto-file-renaming=false',
            '--allow-overwrite=true',
            url,
        ]
        subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True
        ).wait()

    @staticmethod
    def create_download_file(input_file, download_file, quality_url):
        download_file = open(download_file, "w")
        quality_url_root = re.search(r'(.*/)(.*)', quality_url,
                                     re.M | re.I).group(1)

        fh = open(input_file, 'r')
        ts_number = 0
        key_number = 0
        cur_iv = 0
        decode_hashes = []

        for line in fh:
            if '#EXT-X-KEY' in line:
                # Incremenet key number
                key_number = key_number + 1

                # Pull the key url and iv
                in_line_match = re.search(r'.*"(.*)",IV=0x(.*)', line,
                                          re.M | re.I)
                key_url = in_line_match.group(1)
                cur_iv = in_line_match.group(2)

                # Add file to download list
                download_file.write(key_url + '\n')
                download_file.write(' out=temp/keys/' + str(key_number) + '\n')

            elif '.ts\n' in line:
                # Increment ts number
                ts_number += 1

                # Make alternate uri
                alt_quality_url_root = quality_url_root
                if '-l3c.' in alt_quality_url_root:
                    alt_quality_url_root = alt_quality_url_root.replace(
                        '-l3c.', '-akc.')
                else:
                    alt_quality_url_root = alt_quality_url_root.replace(
                        '-akc.', '-l3c.')

                # Add file to download list
                download_file.write(quality_url_root + line.strip(
                    '\n') + '\t' + alt_quality_url_root + line)
                download_file.write(' out=temp/' + str(ts_number) + '.ts\n')

                # Add to decode_hashes
                decode_hashes.append({
                    'key_number': str(key_number),
                    'ts_number': str(ts_number),
                    'iv': str(cur_iv)
                })
        download_file.close()
        return decode_hashes

    def download_nhl(self, url, out_file, retry_errored=False):
        log_file = out_file + "_download.log"
        DOWNLOAD_OPTIONS = " --load-cookies=" + COOKIES_TXT_FILE + " --log='" + log_file + "' --log-level=notice --quiet=true --retry-wait=1 --max-file-not-found=5 --max-tries=5 --header='Accept: */*' --header='Accept-Language: en-US,en;q=0.8' --header='Origin: https://www.nhl.com' -U='Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.97 Safari/537.36' --enable-http-pipelining=true --auto-file-renaming=false --allow-overwrite=true "
        tprint("Starting Download: " + url)

        # Pull url_root
        url_root = re.match('(.*)master_tablet60.m3u8', url,
                            re.M | re.I).group(1)

        # Create the temp and keys directory
        if not os.path.exists('./temp/keys'):
            os.makedirs('./temp/keys')

        # Get the master m3u8
        master_file = "temp/master.m3u8"
        self.download_web_page(url, master_file, log_file)
        quality_url = url_root + self.get_quality_url_from_master(master_file)

        # Get the m3u8 for the quality
        input_file = "temp/input.m3u8"
        self.download_web_page(quality_url, input_file, log_file)

        # Parse m3u8
        # Create files
        download_file = "./temp/download_file.txt"
        decode_hashes = self.create_download_file(input_file, download_file,
                                                  quality_url)

        # User aria2 to download the list
        tprint("starting download of individual video files")
        command = 'aria2c -i ./temp/download_file.txt -j 20 ' + DOWNLOAD_OPTIONS
        subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            shell=True
        ).wait()

        # Repair broken downloads if necessary
        if retry_errored is True:
            redo_broken_downloads(out_file)

        # Create the concat file
        concat_file = open("./temp/concat.txt", "w")

        # Iterate through the decode_hashes and run the decoder function
        tprint("Decode video files")
        for dH in decode_hashes:
            cur_key = 'blank'
            key_val = ''

            # If the cur_key isn't the one from the has then refresh the
            # key_val
            if cur_key != dH['key_number']:
                # Extract the key value
                command = 'xxd -p ./temp/keys/' + dH['key_number']
                p = subprocess.Popen(command, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, shell=True)
                pi = iter(p.stdout.readline, b'')
                for line in pi:
                    key_val = line.strip('\n')
                    cur_key = dH['key_number']
                p.wait()

            # Decode TS
            command = [
                'openssl enc -aes-128-cbc -in "./temp/',
                dH['ts_number'],
                '.ts" -out "./temp/',
                dH['ts_number'],
                '.ts.dec" -d -K',
                key_val,
                '-iv',
                dH['iv'],
            ]
            subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True
            ).wait()

            # Move decoded files over old files
            command = 'mv ./temp/' + dH['ts_number'] + '.ts.dec ./temp/' + dH[
                'ts_number'] + '.ts'
            subprocess.Popen(command, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, shell=True).wait()

            # Add to concat file
            concat_file.write('file ' + dH['ts_number'] + '.ts\n')

        # close concat file
        concat_file.close()

        # merge to single
        command = [
            'ffmpeg',
            '-y',
            '-nostats',
            '-loglevel 0',
            '-f concat',
            '-i ./temp/concat.txt',
            '-c copy',
            '-bsf:a aac_adtstoasc',
            out_file,
        ]
        subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, shell=True).wait()

        # delete the old directory
        command = 'rm -rf ./temp'
        subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, shell=True).wait()

    def create_full_game_stream(self, stream_url, media_auth, bandwidth):
        """"
         SD (800 kbps)|SD (1600 kbps)|HD (3000 kbps)|HD (5000 kbps)
        """

        # Only set bandwidth if it's explicitly set
        if bandwidth != '':
            # Reduce convert bandwidth if composite video selected
            if 'COMPOSITE' in stream_url or 'ISO' in stream_url:
                if int(bandwidth) == 5000:
                    bandwidth = '3500'
                elif int(bandwidth) == 1200:
                    bandwidth = '1500'

        # ARCHIVE
        stream_url = stream_url.replace(
            MASTER_FILE_TYPE,
            bandwidth + 'K/' + bandwidth + '_complete-trimmed.m3u8',
        )

        return stream_url

    def getAuthCookie(self):
        authorization = ''
        try:
            cj = http.cookiejar.LWPCookieJar(COOKIES_LWP_FILE)
            cj.load(COOKIES_LWP_FILE, ignore_discard=True)

            # If authorization cookie is missing or stale, perform login
            for cookie in cj:
                if cookie.name == "Authorization" and not cookie.is_expired():
                    authorization = cookie.value
        except Exception as _:
            pass

        return authorization

    def fetchStream(self, game_id, content_id, event_id):
        stream_url = ''
        media_auth = ''

        authorization = self.getAuthCookie()

        if authorization == '':
            self.login()
            authorization = self.getAuthCookie()
            if authorization == '':
                return stream_url, media_auth, ""

        cj = http.cookiejar.LWPCookieJar(COOKIES_LWP_FILE)
        cj.load(COOKIES_LWP_FILE, ignore_discard=True)

        tprint("Fetching session_key")
        session_key = self.getSessionKey(game_id, event_id, content_id,
                                         authorization)
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj))

        tprint("Checking session key")
        if session_key == '':
            return stream_url, media_auth, ""

        # Org
        url = 'https://mf.svc.nhl.com/ws/media/mf/v2.4/stream?contentId='
        url += str(
            content_id) + '&playbackScenario=HTTP_CLOUD_TABLET_60&platform=IPAD&sessionKey='
        url += urllib.parse.quote_plus(session_key)
        req = urllib.request.Request(url)
        req.add_header("Accept", "*/*")
        req.add_header("Accept-Encoding", "deflate")
        req.add_header("Accept-Language", "en-US,en;q=0.8")
        req.add_header("Connection", "keep-alive")
        req.add_header("Authorization", authorization)
        req.add_header("User-Agent", UA_NHL)
        req.add_header("Proxy-Connection", "keep-alive")

        response = opener.open(req)
        json_source = json.load(response)
        response.close()

        # Pulling out game_info in formated like "2017-03-06_VAN-ANA" for file name prefix
        game_info = self.getGameInfo(json_source)
        tprint("game info=" + game_info)

        # Expecting - values to always be bad i.e.: -3500 is Sign-on restriction: Too many usage attempts
        if json_source['status_code'] < 0:
            tprint(json_source['status_message'])
            # can't handle this at the moment lest get out of here
            exit(1)

        if json_source['status_code'] == 1:
            if \
                    json_source['user_verified_event'][0][
                        'user_verified_content'][0][
                        'user_verified_media_item'][0]['blackout_status'][
                        'status'] == 'BlackedOutStatus':
                msg = "You do not have access to view this content. To watch live games and learn more about blackout restrictions, please visit NHL.TV"
                tprint(msg)
                raise self.BlackoutRestriction

        stream_url = \
            json_source['user_verified_event'][0]['user_verified_content'][0][
                'user_verified_media_item'][0]['url']
        media_auth = str(json_source['session_info']['sessionAttributes'][0][
                             'attributeName']) + "=" + str(
            json_source['session_info']['sessionAttributes'][0][
                'attributeValue'])
        session_key = json_source['session_key']
        setSetting(sid='media_auth', value=media_auth)

        # Update Session Key
        setSetting(sid='session_key', value=session_key)

        # Add media_auth cookie
        ck = http.cookiejar.Cookie(version=0, name='mediaAuth',
                                   value="" + media_auth.replace('mediaAuth=',
                                                                 '') + "",
                                   port=None, port_specified=False,
                                   domain='.nhl.com', domain_specified=True,
                                   domain_initial_dot=True, path='/',
                                   path_specified=True, secure=False,
                                   expires=(int(time.time()) + 7500),
                                   discard=False, comment=None,
                                   comment_url=None, rest={}, rfc2109=False)
        cj = http.cookiejar.LWPCookieJar(COOKIES_LWP_FILE)
        cj.load(COOKIES_LWP_FILE, ignore_discard=True)
        cj.set_cookie(ck)
        cj.save(ignore_discard=False)

        return stream_url, media_auth, game_info

    def getGameInfo(self, json_source=json):
        """
        ==================================================
        Game info for file prefix like 2017-03-06_VAN-ANA
        ==================================================

        Arguments:
            json_source (json): The first parameter.

        Returns:
            str: game info string like 2017-03-06_VAN-ANA
        """
        game_info = \
            json_source['user_verified_event'][0]['user_verified_content'][0][
                'name'].replace(":", "|")
        game_time, game_teams, _ = game_info.split(" | ")
        game_teams = game_teams.split()[0] + "-" + game_teams.split()[2]
        return game_time + "_" + game_teams

    def getSessionKey(self, game_id, event_id, content_id, authorization):
        session_key = str(getSetting(sid="session_key"))

        if session_key == '':
            tprint("need to fetch new session key")
            epoch_time_now = str(int(round(time.time() * 1000)))

            url = 'https://mf.svc.nhl.com/ws/media/mf/v2.4/stream?eventId='
            url += event_id + '&format=json&platform=WEB_MEDIAPLAYER&subject=NHLTV&_='
            url += epoch_time_now

            req = urllib.request.Request(url)
            req.add_header("Accept", "application/json")
            req.add_header("Accept-Encoding", "deflate")
            req.add_header("Accept-Language", "en-US,en;q=0.8")
            req.add_header("Connection", "keep-alive")
            req.add_header("Authorization", authorization)
            req.add_header("User-Agent", UA_PC)
            req.add_header("Origin", "https://www.nhl.com")
            req.add_header("Referer",
                           "https://www.nhl.com/tv/" + game_id + "/" + event_id + "/" + content_id)

            response = urllib.request.urlopen(req)
            json_source = json.load(response)
            response.close()
            tprint("status_code" + str(json_source['status_code']))
            # Expecting - values to always be bad i.e.: -3500 is Sign-on restriction: Too many usage attempts
            if json_source['status_code'] < 0:
                tprint(json_source['status_message'])
                # can't handle this at the moment lest get out of here
                return 'error'

            tprint("REQUESTED SESSION KEY")

            if json_source['status_code'] == 1:
                if \
                        json_source['user_verified_event'][0][
                            'user_verified_content'][
                            0]['user_verified_media_item'][0][
                            'blackout_status'][
                            'status'] == 'BlackedOutStatus':
                    msg = "You do not have access to view this content. To watch live games and learn more about blackout restrictions, please visit NHL.TV"
                    tprint(msg)
                    return 'blackout'
            session_key = str(json_source['session_key'])
            setSetting(sid='session_key', value=session_key)

        return session_key

    def login(self):
        # Check if username and password are provided
        print("Need to login to NHL Gamecenter")
        if (self.userName == "") or (self.passWord == ""):
            self.userName = input("Username: ")
            self.passWord = getpass.getpass()

        cj = http.cookiejar.LWPCookieJar(COOKIES_LWP_FILE)
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj))

        try:
            cj.load(COOKIES_LWP_FILE, ignore_discard=True)
        except Exception as _:
            pass

        # Get Token
        url = 'https://user.svc.nhl.com/oauth/token?grant_type=client_credentials'
        req = urllib.request.Request(url)
        req.add_header("Accept", "application/json")
        req.add_header("Accept-Encoding", "gzip, deflate, sdch")
        req.add_header("Accept-Language", "en-US,en;q=0.8")
        req.add_header("User-Agent", UA_PC)
        req.add_header("Origin", "https://www.nhl.com")

        # from https:/www.nhl.com/tv?affiliated=NHLTVLOGIN
        req.add_header("Authorization",
                       "Basic d2ViX25obC12MS4wLjA6MmQxZDg0NmVhM2IxOTRhMThlZjQwYWM5ZmJjZTk3ZTM=")

        response = opener.open(req, '')
        json_source = json.load(response)
        authorization = self.getAuthCookie()
        if authorization == '':
            authorization = json_source['access_token']
        response.close()

        url = 'https://gateway.web.nhl.com/ws/subscription/flow/nhlPurchase.login'
        login_data = '{"nhlCredentials":{"email":"' + self.userName + '","password":"' + self.passWord + '"}}'

        req = urllib.request.Request(url, data=login_data, headers={
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.8",
            "Content-Type": "application/json",
            "Origin": "https://www.nhl.com",
            "Authorization": authorization,
            "Connection": "keep-alive",
            "User-Agent": UA_PC
        })
        try:
            response = opener.open(req)
        except HTTPError as e:
            tprint('The server couldn\'t fulfill the request.')
            tprint('Error code: ' + e.code)
            tprint(url)

            # Error 401 for invalid login
            if e.code == 401:
                msg = "Please check that your username and password are correct"
                tprint(msg)

        response.close()
        cj.save(ignore_discard=True)

    def logout(self, display_msg=None):
        cj = http.cookiejar.LWPCookieJar(COOKIES_LWP_FILE)
        try:
            cj.load(COOKIES_LWP_FILE, ignore_discard=True)
        except Exception as _:
            pass

        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj))
        url = 'https://account.nhl.com/ui/rest/logout'

        req = urllib.request.Request(url, data='', headers={
            "Accept": "*/*",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Language": "en-US,en;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": "https://account.nhl.com/ui/SignOut?lang=en",
            "Connection": "close",
            "User-Agent": UA_PC
        })

        response = None
        try:
            response = opener.open(req)
        except HTTPError as e:
            tprint("The server couldn't fulfill the request.")
            tprint('Error code: ' + e.code)
            tprint(url)
        finally:
            if response is not None:
                response.close()

        if display_msg == 'true':
            setSetting(sid='session_key', value='')

    def checkForNewGame(self, startDate="YYYY-MM-DD", endDate="YYYY-MM-DD"):
        """
        Fetches game schedule between two dates and returns it as a json source
        """
        tprint(
            'Checking for new game between ' + startDate + " and " + endDate)
        url = 'http://statsapi.web.nhl.com/api/v1/schedule?expand=schedule.teams,schedule.linescore,schedule.scoringplays,schedule.game.content.media.epg&startDate='
        url += startDate + '&endDate=' + endDate + '&site=en_nhl&platform=playstation'
        tprint('Looking up games @ ' + url)
        # url = 'http://statsapi.web.nhl.com/api/v1/schedule?expand=schedule.teams,schedule.linescore,schedule.scoringplays,schedule.game.content.media.epg&startDate=2016-04-10&endDate=2016-04-10&site=en_nhl&platform=playstation'
        req = urllib.request.Request(url)
        req.add_header('Connection', 'close')
        req.add_header('User-Agent', UA_PS4)
        response = urllib.request.urlopen(req)
        return json.load(response)

    def lookForTheNextGameToGet(self, json_source):
        """
        Get NHL TV Team names
        Class parses all teams so that you can pull from it.

        Arguments:
            json_source (json): json object form schelude.gamecontent.media.epg

        Returns:
            game (json): Json object of next game
            favTeamHomeAway (string): String if the teams a "AWAY" or "HOME" feed

        """
        favTeamHomeAway = 'HOME'
        lastGame = getSetting('lastGameID')

        for jd in json_source['dates']:
            for jg in jd['games']:
                homeTeamId = int(jg['teams']['home']['team']["id"])
                awayTeamId = int(jg['teams']['away']['team']["id"])
                gameID = jg['gamePk']

                # Print out for debugging
                #                 print("DownloadNHL.lookForTheNextGameToGet: self.teamID=" + str(self.teamID) + " homeTeamId=" + str(homeTeamId) + " awayTeamId=" + str(awayTeamId) + " gameID=" + str(gameID) + " lastGame=" + str(lastGame))
                if ((
                        homeTeamId == self.teamID or awayTeamId == self.teamID) and gameID > lastGame):
                    if (awayTeamId == self.teamID):
                        favTeamHomeAway = 'AWAY'
                    return (jg, favTeamHomeAway)
        raise self.NoGameFound

    def get_game_id(self):
        """

        :return:
        """
        current_time = datetime.now()
        startDate = (current_time.date() - timedelta(days=4)).isoformat()
        endDate = current_time.date().isoformat()
        json_source = self.checkForNewGame(startDate, endDate)

        # Go through all games in the file and look for the next game
        gameToGet, favTeamHomeAway = self.lookForTheNextGameToGet(json_source)

        bestScore = -1
        bestEpg = None
        for epg in gameToGet['content']['media']['epg'][0]['items']:
            score = 0
            if (epg['language'] == 'eng'):
                score = score + 100
            if (epg['mediaFeedType'] == favTeamHomeAway):
                score = score + 50
            if (score > bestScore):
                bestScore = score
                bestEpg = epg

        # If there isn't a bestEpg then treat it like an archive case
        if bestEpg is None:
            bestEpg = {}
            bestEpg['mediaState'] = ''

        # If the feed is good to go then return the info
        if (bestEpg['mediaState'] == 'MEDIA_ARCHIVE'):
            gameID = gameToGet['gamePk']
            contentID = str(bestEpg['mediaPlaybackId'])
            eventID = str(bestEpg['eventId'])
            tprint("Found a game: " + str(gameID))
            waitTimeInMin = 0
            return gameID, contentID, eventID, waitTimeInMin

        # If it is not then figure out how long to wait and wait
        # If the game hasn't started then wait until 3 hours after the game has started
        startDateTime = datetime.strptime(gameToGet['gameDate'],
                                          '%Y-%m-%dT%H:%M:%SZ')
        if (startDateTime > datetime.utcnow()):
            waitUntil = startDateTime + timedelta(minutes=150)
            waitTimeInMin = ((
                                     waitUntil - datetime.utcnow()).total_seconds()) / 60
            tprint("Game scheduled for " + gameToGet[
                'gameDate'] + " hasn't started yet")
            return None, None, None, waitTimeInMin

        raise self

    def downloadStream(self, stream_url, outputFile):
        tprint('Downloading the stream...')
        command = 'bash ./nhldl.sh "' + stream_url + '" ' + self.quality
        print(command)
        p = subprocess.Popen(command, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, shell=True)
        pi = iter(p.stdout.readline, b'')
        downloadFile = None
        downloadDirectory = None

        outfile = open(outputFile + '.log', 'w')
        for line in pi:
            outfile.write(line)
            if ('Fetching master m3u8 fh' in line):
                fh = re.search(r'.*/NHL_GAME_VIDEO_(.*)/.*', line, re.M | re.I)
                downloadFile = 'NHL_GAME_VIDEO_' + fh.group(1) + '.mp4'
                downloadDirectory = 'NHL_GAME_VIDEO_' + fh.group(1)

        # Wait for it to finish
        p.wait()
        outfile.close()

        tprint("Stream downloaded. Cleaning up!")

        # Rename the output fh
        command = 'mv ' + downloadFile + ' ' + outputFile
        subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, shell=True).wait()

        # Remove the old directory
        command = 'rm -rf ' + downloadDirectory
        subprocess.Popen(command, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, shell=True).wait()

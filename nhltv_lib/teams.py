import urllib.request, urllib.error, urllib.parse
import json

class Team(object):
    fullName = "Detroit Red Wings"
    id = 17
    abbreviation = "DET"

    def __str__(self):
        return str(self.__dict__)


class Teams(object):
    """
    ==================================================
    Get NHL TV Team names
    ==================================================
    Class parses all teams so that you can pull from it.

    Arguments:
        _parseTeam (etree): ElementTree root

    Returns:
        Team: Team object
    """
    team = Team()
    teams = {}
    user_agent = 'PS4Application libhttp/1.000 (PS4) libhttp/3.15 (PlayStation 4)'
    url = 'https://statsapi.web.nhl.com/api/v1/teams?'

    def getTeam(self, search):
        """
        ==================================================
        Get Team
        ==================================================

        Arguments:
            search (int): by team id number like 17
            search (STR): search by teams TriCode/abbreviation like "DET"
            search (str): search by team name like "Detroit Red Wings"

        Returns:
            Team: Team object
        """
        if len(self.teams) < 3:
            self._fetchTeams()

        if isinstance(search, int):
            return self._searchTeamById(search)
        if search.isdigit():
            return self._searchTeamById(int(search))
        if search.isupper():
            return self._searchTeamByAbbreviation(search)
        return self._searchTeamName(search)

    def _fetchTeams(self):
        req = urllib.request.Request(self.url)
        req.add_header('Connection', 'close')
        req.add_header('User-Agent', self.user_agent)
        try: 
            response = urllib.request.urlopen(req)
        except urllib.error.HTTPError as err:
            raise LookupError('ERROR ' + str(err.code) + ' %s' % self.url)
        data = json.load(response)
        self._parseGameContentSchedule(data)
        response.close()

    def _parseTeam(self, team):
        t = Team()
        teamName = team["name"]
        # replace French letters with English (Montreal Canadiens):
        t.fullName = teamName.replace("\xc3\xa9", "e")
        t.id = int(str(team["id"]))
        t.abbreviation = str(team["abbreviation"])
        self.teams[t.abbreviation] = t

    def _parseGameContentSchedule(self, data):
        for team in data["teams"]:
            self._parseTeam(team)

    def _searchTeamByAbbreviation(self, search=str):
        return self.teams[search]

    def _searchTeamById(self, search=int):
        for team in self:
            if search is team.id:
                return team
        raise LookupError('Could not find team with id %s' % search)

    def _searchTeamName(self, search):
        for team in list(self.teams.values()):
            if search in team.fullName:
                return team
        raise LookupError('Could not find team with id %s' % search)

    def __iter__(self):
        return iter(list(self.teams.values()))

    def __len__(self):
        return len(list(self.teams.items()))

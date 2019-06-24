

class Borg(object):
    """ base class of monostate pattern
        ref : https://github.com/faif/python-patterns/blob/master/patterns/creational/borg.py
    """
    _shared_state = {}

    def __init__(self):
        self.__dict__ = self._shared_state

    def __str__(self):
        represent = [f'{key} : {value}\n' for key, value in self.__dict__.items()]
        return ''.join(represent)


class PeerState(Borg):
    """ TODO : status_cache must be thread safe

    peer_port = 8080
    peer_target = '' # 'localhost'
    rest_target = '' # '127.0.0.1:9000'
    peer_id = '' # 'peer_id'
    channel_infos = {} # {'peer': '1231414141', 'order': 1}
    node_key = bytes()
    self.status_cache = {}  # {channel:status}
    """

from charmhelpers.core import hookenv


def charm_status(msg):
    if not msg:
        return 'blocked', 'unknown error'
    if msg.find('mongo-addr') == -1:
        return 'blocked', msg
    if hookenv.relation_ids('db'):
        # We've got a mongodb relation, but we're still getting
        # an error with "mongo-addr" in it. That's probably
        # because the mongodb application at the other
        # end of the relation hasn't set its attributes yet.
        return 'waiting', 'waiting for db relation'
    return 'blocked', 'need db relation'

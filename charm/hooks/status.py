from charmhelpers.core import hookenv

databases = ['mongodb', 'postgres']


def charm_status(msg):
    if not msg:
        return 'blocked', 'unknown error'
    if msg.find('storage') == -1:
        return 'blocked', msg
    for db in databases:
        if hookenv.relation_ids(db):
            # We've got a database relation, but we're still getting
            # an error with "storage" in it. That's probably
            # because the application at the other
            # end of the relation hasn't set its attributes yet.
            return 'waiting', 'waiting for {} relation'.format(db)
    return 'blocked', 'need {} relation'.format(' or '.join(databases))

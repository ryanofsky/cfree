ACE_ROOT = '/home/russ/devel/cfree/ACE_wrappers'

import os.path

env = Environment(CPPPATH=ACE_ROOT,
                  LIBPATH=os.path.join(ACE_ROOT, 'lib'))

env.Program(['cfree.cpp'], LIBS=['crypto++'])
env.Program(['asynch.cpp'], LIBS=['ACE'],
	    RPATH=os.path.join(ACE_ROOT, 'lib'))

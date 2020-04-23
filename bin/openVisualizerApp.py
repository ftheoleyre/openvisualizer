# Copyright (c) 2010-2013, Regents of the University of California. 
# All rights reserved. 
#  
# Released under the BSD 3-Clause license as published at the link below.
# https://openwsn.atlassian.net/wiki/display/OW/License

"""
Contains application model for OpenVisualizer. Expects to be called by
top-level UI module.  See main() for startup use.
"""

import json
import logging
import logging.config
import os
import signal
import sys
from argparse import ArgumentParser

import openvisualizer.openvisualizer_utils as u
from openvisualizer import appdirs
from openvisualizer.OVtracer import OVtracer
from openvisualizer.SimEngine import SimEngine, MoteHandler
from openvisualizer.eventBus import eventBusMonitor
from openvisualizer.jrc import jrc
from openvisualizer.motehandler.moteconnector import moteconnector
from openvisualizer.motehandler.moteprobe import moteprobe
from openvisualizer.motehandler.motestate import motestate
from openvisualizer.openlbr import openlbr
from openvisualizer.opentun.opentun import OpenTun
from openvisualizer.rpl import rpl
from openvisualizer.rpl import topology

log = logging.getLogger('openVisualizerApp')


class OpenVisualizerApp(object):
    """
    Provides an application model for OpenVisualizer. Provides common,
    top-level functionality for several UI clients.
    """

    def __init__(self, conf_dir, data_dir, log_dir, simulator_mode, num_motes, trace, debug, use_page_zero,
                 sim_topology, iotlab_motes, testbed_motes, path_topo, mqtt_broker_address, opentun):

        # store params
        self.conf_dir = conf_dir
        self.data_dir = data_dir
        self.log_dir = log_dir
        self.simulator_mode = simulator_mode
        self.num_motes = num_motes
        self.trace = trace
        self.debug = debug
        self.use_page_zero = use_page_zero
        self.iotlab_motes = iotlab_motes
        self.testbed_motes = testbed_motes
        self.path_topo = path_topo

        # local variables
        self.ebm = eventBusMonitor.eventBusMonitor()
        self.openlbr = openlbr.OpenLbr(use_page_zero)
        self.rpl = rpl.RPL()
        self.jrc = jrc.JRC()
        self.topology = topology.Topology()
        self.dagroot_list = []
        # create opentun call last since indicates prefix
        self.opentun = OpenTun.create(opentun)
        if self.simulator_mode:
            self.simengine = SimEngine.SimEngine(sim_topology)
            self.simengine.start()

        topo = None
        # import the number of motes from json file given by user (if the path_topo option is enabled)
        if self.path_topo and self.simulator_mode:
            try:
                topo_config = open(path_topo)
                topo = json.load(topo_config)
                self.num_motes = len(topo['motes'])
            except Exception as err:
                print err
                self.close()
                os.kill(os.getpid(), signal.SIGTERM)

        # create a moteprobe for each mote
        if self.simulator_mode:
            # in "simulator" mode, motes are emulated
            sys.path.append(os.path.join(self.data_dir, 'sim_files'))
            import oos_openwsn

            MoteHandler.readNotifIds(os.path.join(self.data_dir, 'sim_files', 'openwsnmodule_obj.h'))
            self.moteProbes = []
            for _ in range(self.num_motes):
                mote_handler = MoteHandler.MoteHandler(oos_openwsn.OpenMote())
                self.simengine.indicateNewMote(mote_handler)
                self.moteProbes += [moteprobe.MoteProbe(mqtt_broker_address, emulated_mote=mote_handler)]
        elif self.iotlab_motes:
            # in "IoT-LAB" mode, motes are connected to TCP ports

            self.moteProbes = [
                moteprobe.MoteProbe(mqtt_broker_address, iotlab_mote=p) for p in self.iotlab_motes.split(',')
            ]
        elif self.testbed_motes:
            motes_finder = moteprobe.OpentestbedMoteFinder(mqtt_broker_address)
            self.moteProbes = [
                moteprobe.MoteProbe(mqtt_broker_address, testbedmote_eui64=p)
                for p in motes_finder.get_opentestbed_motelist()
            ]

        else:
            # in "hardware" mode, motes are connected to the serial port

            self.moteProbes = [
                moteprobe.MoteProbe(mqtt_broker_address, serial_port=p) for p in moteprobe.find_serial_ports()
            ]

        # create a MoteConnector for each MoteProbe
        self.mote_connectors = [moteconnector.MoteConnector(mp) for mp in self.moteProbes]

        # create a MoteState for each MoteConnector
        self.mote_states = [motestate.MoteState(mc) for mc in self.mote_connectors]

        # boot all emulated motes, if applicable
        if self.simulator_mode:
            self.simengine.pause()
            now = self.simengine.timeline.getCurrentTime()
            for rank in range(self.simengine.getNumMotes()):
                mote_handler = self.simengine.getMoteHandler(rank)
                self.simengine.timeline.scheduleEvent(
                    now,
                    mote_handler.getId(),
                    mote_handler.hwSupply.switchOn,
                    mote_handler.hwSupply.INTR_SWITCHON
                )
            self.simengine.resume()

        # import the topology from the json file
        if self.path_topo and self.simulator_mode and 'motes' in topo:

            # delete each connections automatically established during motes creation
            connections_to_delete = self.simengine.propagation.retrieveConnections()
            for co in connections_to_delete:
                from_mote = int(co['fromMote'])
                to_mote = int(co['toMote'])
                self.simengine.propagation.deleteConnection(from_mote, to_mote)

            motes = topo['motes']
            for mote in motes:
                mh = self.simengine.getMoteHandlerById(mote['id'])
                mh.setLocation(mote['lat'], mote['lon'])

            # implements new connections
            connect = topo['connections']
            for co in connect:
                from_mote = int(co['fromMote'])
                to_mote = int(co['toMote'])
                pdr = float(co['pdr'])
                self.simengine.propagation.createConnection(from_mote, to_mote)
                self.simengine.propagation.updateConnection(from_mote, to_mote, pdr)

            # store DAGroot moteids in DAGrootList
            dagroot_l = topo['DAGrootList']
            for DAGroot in dagroot_l:
                hexa_dagroot = hex(DAGroot)
                hexa_dagroot = hexa_dagroot[2:]
                prefixLen = 4 - len(hexa_dagroot)

                prefix = ""
                for i in range(prefixLen):
                    prefix += "0"
                moteid = prefix + hexa_dagroot
                self.dagroot_list.append(moteid)

        # start tracing threads
        if self.trace:
            logging.config.fileConfig(
                os.path.join(self.conf_dir, 'trace.conf'), {'logDir': _force_slash_sep(self.log_dir, self.debug)}
            )
            OVtracer()

    # ======================== public ==========================================

    def close(self):
        """ Closes all thread-based components """
        log.info('Closing OpenVisualizer')

        self.opentun.close()
        self.rpl.close()
        self.jrc.close()
        for probe in self.moteProbes:
            probe.close()

    def get_mote_state(self, moteid):
        """
        Returns the MoteState object for the provided connected mote.
        :param moteid: 16-bit ID of mote
        :rtype: MoteState or None if not found
        """

        for ms in self.mote_states:
            id_manager = ms.get_state_elem(ms.ST_IDMANAGER)
            if id_manager and id_manager.get_16b_addr():
                addr = ''.join(['%02x' % b for b in id_manager.get_16b_addr()])
                if addr == moteid:
                    return ms
        else:
            return None

    def get_motes_connectivity(self):
        motes = []
        states = []
        edges = []
        src_s = None

        for ms in self.mote_states:
            id_manager = ms.get_state_elem(ms.ST_IDMANAGER)
            if id_manager and id_manager.get_16b_addr():
                src_s = ''.join(['%02X' % b for b in id_manager.get_16b_addr()])
                motes.append(src_s)
            neighbor_table = ms.get_state_elem(ms.ST_NEIGHBORS)
            for neighbor in neighbor_table.data:
                if len(neighbor.data) == 0:
                    break
                if neighbor.data[0]['used'] == 1 and neighbor.data[0]['parentPreference'] == 1:
                    dst_s = ''.join(['%02X' % b for b in neighbor.data[0]['addr'].addr[-2:]])
                    edges.append({'u': src_s, 'v': dst_s})
                    break

        motes = list(set(motes))
        for mote in motes:
            d = {'id': mote, 'value': {'label': mote}}
            states.append(d)
        return states, edges

    def get_mote_dict(self):
        """ Returns a dictionary with key-value entry: (moteid: serialport) """
        mote_dict = {}
        for ms in self.mote_states:
            addr = ms.get_state_elem(motestate.MoteState.ST_IDMANAGER).get_16b_addr()
            if addr:
                mote_dict[''.join(['%02x' % b for b in addr])] = ms.mote_connector.serialport
            else:
                mote_dict[ms.mote_connector.serialport] = None
        return mote_dict


# ============================ main ============================================

DEFAULT_MOTE_COUNT = 3


def main(parser=None):
    """
    Entry point for application startup by UI. Parses common arguments.
    :param parser: Optional ArgumentParser passed in from enclosing UI module to allow that module to pre-parse
    specific arguments
    :rtype: openVisualizerApp object
    """

    if parser is None:
        parser = ArgumentParser()

    _add_parser_args(parser)
    arg_space = parser.parse_args()

    conf_dir, data_dir, log_dir = _init_external_dirs(arg_space.appdir, arg_space.debug)

    # Must use a '/'-separated path for log dir, even on Windows.
    logging.config.fileConfig(os.path.join(conf_dir, 'logging.conf'),
                              {'logDir': _force_slash_sep(log_dir, arg_space.debug)})

    if arg_space.path_topo:
        arg_space.simulator_mode = True
        arg_space.num_motes = 0
        arg_space.sim_topology = "fully-meshed"
        # --path_topo
    elif arg_space.num_motes > 0:
        # --simCount implies --sim
        arg_space.simulator_mode = True
    elif arg_space.simulator_mode:
        # default count when --simCount not provided
        arg_space.num_motes = DEFAULT_MOTE_COUNT

    log.info('Initializing OpenVisualizerApp with options:\n\t{0}'.format(
        '\n    '.join(['appdir      = {0}'.format(arg_space.appdir),
                       'sim         = {0}'.format(arg_space.simulator_mode),
                       'simCount    = {0}'.format(arg_space.num_motes),
                       'trace       = {0}'.format(arg_space.trace),
                       'debug       = {0}'.format(arg_space.debug),
                       'testbed_motes= {0}'.format(arg_space.testbed_motes),

                       'use_page_zero = {0}'.format(arg_space.use_page_zero)],
                      )))
    log.info('Using external dirs:\n\t{0}'.format(
        '\n    '.join(['conf     = {0}'.format(conf_dir),
                       'data     = {0}'.format(data_dir),
                       'log      = {0}'.format(log_dir)],
                      )))
    log.info('sys.path:\n\t{0}'.format('\n\t'.join(str(p) for p in sys.path)))

    return OpenVisualizerApp(
        conf_dir=conf_dir,
        data_dir=data_dir,
        log_dir=log_dir,
        simulator_mode=arg_space.simulator_mode,
        num_motes=arg_space.num_motes,
        trace=arg_space.trace,
        debug=arg_space.debug,
        use_page_zero=arg_space.use_page_zero,
        sim_topology=arg_space.sim_topology,
        iotlab_motes=arg_space.iotlab_motes,
        testbed_motes=arg_space.testbed_motes,
        path_topo=arg_space.path_topo,
        mqtt_broker_address=arg_space.mqtt_broker_address,
        opentun=arg_space.opentun
    )


def _add_parser_args(parser):
    parser.add_argument('-a', '--appDir',
                        dest='appdir',
                        default='.',
                        action='store',
                        help='working directory'
                        )
    parser.add_argument('-s', '--sim',
                        dest='simulator_mode',
                        default=False,
                        action='store_true',
                        help='simulation mode, with default of {0} motes'.format(DEFAULT_MOTE_COUNT)
                        )
    parser.add_argument('-n', '--simCount',
                        dest='num_motes',
                        type=int,
                        default=0,
                        help='simulation mode, with provided mote count'
                        )
    parser.add_argument('-t', '--trace',
                        dest='trace',
                        default=False,
                        action='store_true',
                        help='enables memory debugging'
                        )
    parser.add_argument('-st', '--simTopology',
                        dest='sim_topology',
                        default='',
                        action='store',
                        help='force a certain toplogy (simulation mode only)'
                        )
    parser.add_argument('-d', '--debug',
                        dest='debug',
                        default=False,
                        action='store_true',
                        help='enables application debugging'
                        )
    parser.add_argument('-pagez', '--usePageZero',
                        dest='use_page_zero',
                        default=False,
                        action='store_true',
                        help='use page number 0 in page dispatch (only works with one-hop)'
                        )
    parser.add_argument('-iotm', '--iotlabMotes',
                        dest='iotlab_motes',
                        default='',
                        action='store',
                        help='comma-separated list of IoT-LAB motes (e.g. "wsn430-9,wsn430-34,wsn430-3")'
                        )
    parser.add_argument('-tb', '--opentestbed',
                        dest='testbed_motes',
                        default=False,
                        action='store_true',
                        help='connect motes from opentestbed'
                        )
    parser.add_argument('--mqtt-broker-address',
                        dest='mqtt_broker_address',
                        default='argus.paris.inria.fr',
                        action='store',
                        help='MQTT broker address to use'
                        )
    parser.add_argument('--opentun',
                        dest='opentun',
                        default=False,
                        action='store_true',
                        help='Use TUN device to route to the Internet (requires superuser privileges, e.g., sudo)'
                        )
    parser.add_argument('-i', '--pathTopo',
                        dest='path_topo',
                        default='',
                        action='store',
                        help='a topology can be loaded from a json file'
                        )
    parser.add_argument('-ro', '--root',
                        dest='root',
                        default='',
                        action='store',
                        help='set mote associated to serial port as root'
                        )


def _force_slash_sep(ospath, debug):
    """
    Converts a Windows-based path to use '/' as the path element separator.
    :param ospath: A relative or absolute path for the OS on which this process is running
    :param debug: If true, print extra logging info
    """

    if os.sep == '/':
        return ospath

    head = ospath
    path_list = []
    while True:
        head, tail = os.path.split(head)
        if tail == '':
            path_list.insert(0, head.rstrip('\\'))
            break
        else:
            path_list.insert(0, tail)

    path_str = '/'.join(path_list)
    if debug:
        print path_str
    return path_str


def _init_external_dirs(appdir, debug):
    """
    Find and define conf_dir for config files and data_dir for static data. Also
    return log_dir for logs. There are several possiblities, searched in the order
    described below.

    1. Provided from command line, appdir parameter
    2. In the directory containing openVisualizerApp.py
    3. In native OS site-wide config and data directories
    4. In the openvisualizer package directory

    The directories differ only when using a native OS site-wide setup.

    :param debug: If true, print extra logging info
    :returns: 3-Tuple with config dir, data dir, and log dir
    :raises: RuntimeError if files/directories not found as expected
    """
    if not appdir == '.':
        if not _verify_conf_path(appdir):
            raise RuntimeError('Config file not in expected directory: {0}'.format(appdir))
        if debug:
            print 'App data found via appdir'
        return appdir, appdir, appdir

    file_dir = os.path.dirname(__file__)
    if _verify_conf_path(file_dir):
        if debug:
            print 'App data found via openVisualizerApp.py'
        return file_dir, file_dir, file_dir

    conf_dir = appdirs.site_config_dir('openvisualizer', 'OpenWSN')
    # Must use system log dir on Linux since running as superuser.
    linux_log_dir = '/var/log/openvisualizer'
    if _verify_conf_path(conf_dir):
        if not sys.platform.startswith('linux'):
            raise RuntimeError('Native OS external directories supported only on Linux')

        data_dir = appdirs.site_data_dir('openvisualizer', 'OpenWSN')
        log_dir = linux_log_dir
        if os.path.exists(data_dir):
            if not os.path.exists(log_dir):
                os.mkdir(log_dir)
            if debug:
                print 'App data found via native OS'
            return conf_dir, data_dir, log_dir
        else:
            raise RuntimeError('Cannot find expected data directory: {0}'.format(data_dir))

    data_dir = os.path.join(os.path.dirname(u.__file__), 'data')
    if _verify_conf_path(data_dir):
        if sys.platform == 'win32':
            log_dir = appdirs.user_log_dir('openvisualizer', 'OpenWSN', opinion=False)
        else:
            log_dir = linux_log_dir
        if not os.path.exists(log_dir):
            # Must make intermediate directories on Windows
            os.makedirs(log_dir)
        if debug:
            print 'App data found via openvisualizer package'

        return data_dir, data_dir, log_dir
    else:
        raise RuntimeError('Cannot find expected data directory: {0}'.format(data_dir))


def _verify_conf_path(conf_dir):
    """ Returns True if OpenVisualizer conf files exist in the provided directory. """
    conf_path = os.path.join(conf_dir, 'openvisualizer.conf')
    return os.path.isfile(conf_path)

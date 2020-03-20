import cobra.mit.access
import cobra.mit.request
import cobra.mit.session
import cobra.model.fv
import cobra.model.ip
import cobra.model.vz
import cobra.model.pol
import cobra.model.vpc
import cobra.model.fvns
import cobra.model.lacp
import cobra.model.phys
import cobra.model.infra
import cobra.model.l3ext
import cobra.model.fabric
import cobra.model.cdp
import cobra.model.lldp

import time

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def prGreen(skk): print("\033[92m{}\033[00m" .format(skk))
def prRed(skk): print("\033[91m{}\033[00m" .format(skk))
def prLightGray(skk): print("\033[97m{}\033[00m" .format(skk))
def prBlue(skk): print("\033[34m{}\033[00m" .format(skk))

def apic_login(URL, USER, PASSWORD):
    """

    :param URL: IP or name, ie sandboxapicdc.cisco.com
    :param USER:
    :param PASSWORD:

    """

    ls = cobra.mit.session.LoginSession('https://' + URL, USER, PASSWORD)
    md = cobra.mit.access.MoDirectory(ls)
    md.login()

    print("Logged into %s" % URL)
    return md
def push_to_apic(md, topMo):
    """ Push config to APIC
    :param md: Model Directory from login information
    :param top_mo: built-up top level object

    """
    print("Push config to APIC")
    time.sleep(0.300)

    c = cobra.mit.request.ConfigRequest()
    c.addMo(topMo)
    md.commit(c)

    prRed("Done !\n")
def Create_linkLevelPol(md, name, autoNeg, speed):
    """

    create link level interface policy

    :param md: login session created from apic_login functions
    :param name: the name of link level Policy
    :param autoNeg: 'on', 'off'
    :param speed: '100M', '1G', '10G', '25G', '100G', 'inherit', 'DEFAULT'

    """

    print("Defining Link Level Interface Policy")
    print("... name : ", end='')
    prBlue(name)
    print("... Auto Negotiation : ", end='')
    prBlue(autoNeg)
    print("... Speed : ", end='')
    prBlue(speed)

    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/hintfpol-%s' % name)
    topMo = md.lookupByDn(top_dn.getParent())

    cobra.model.fabric.HIfPol(topMo, name=name, autoNeg=autoNeg, speed=speed)
    push_to_apic(md, topMo)
def Create_cdpIfPol(md, name, adminSt):
    """

    create cdp interface policy

    :param md: login session created from apic_login functions
    :param name: the name of cdp Policy
    :param adminSt: 'enabled', 'disabled'

    """

    print("Defining CDP Interface Policy")
    print("... name : ", end='')
    prBlue(name)
    print("... adminSt : ", end='')
    prBlue(adminSt)

    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/cdpIfP-%s' % name)
    topMo = md.lookupByDn(top_dn.getParent())

    cobra.model.cdp.IfPol(topMo, name=name, adminSt=adminSt)
    push_to_apic(md,topMo)
def Create_lldpIfPol(md, name, adminRxSt, adminTxSt):
    """

    create lldp interface policy

    :param md: login session created from apic_login functions
    :param name: the name of lldp Policy
    :param adminRxSt: 'enabled', 'disabled'
    :param adminTxSt: 'enabled', 'disabled'

    """

    print("Defining LLDP Interface Policy")
    print("... name : ", end='')
    prBlue(name)
    print("... adminRxSt : ", end='')
    prBlue(adminRxSt)
    print("... adminTxSt : ", end='')
    prBlue(adminTxSt)

    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/lldpIfP-%s' % name)
    topMo = md.lookupByDn(top_dn.getParent())

    cobra.model.lldp.IfPol(topMo, name=name, adminRxSt=adminRxSt, adminTxSt=adminTxSt)
    push_to_apic(md,topMo)
def Create_lacpPol(md, name, mode):
    """

    create lldp interface policy

    :param md: login session created from apic_login functions
    :param name: the name of lacp Policy
    :param mode: 'off', 'active', 'passive', 'mac-pin', 'mac-pin-nicload'

    """

    print("Defining LACP Interface Policy")
    print("... name : ", end='')
    prBlue(name)
    print("... LACP Mode : ", end='')
    prBlue(mode)

    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/lacplagp-%s' % name)
    topMo = md.lookupByDn(top_dn.getParent())

    cobra.model.lacp.LagPol(topMo, name=name, mode=mode)
    push_to_apic(md,topMo)
def Create_aaep(md, name, descr):
    """

    create Attachable Access Entity Profile

    :param md: login session created from apic_login functions
    :param name: the name of aaep
    :param descr: description

    """

    print("Defining Attachable Access Entity Profile")
    print("... name : ", end='')
    prBlue(name)
    print("... descr : ", end='')
    prBlue(descr)

    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/attentp-%s' % name)
    topMo = md.lookupByDn(top_dn.getParent())

    cobra.model.infra.AttEntityP(topMo, name=name, descr=descr)
    push_to_apic(md,topMo)
def Create_accessPG(md, name, linkLevel, cdp, lldp, aaep):
    """

    create Leaf Access Port Policy Group

    :param md: login session created from apic_login functions
    :param name: the name of Policy Group
    :param linkLevel: Link Level interface Policy name
    :param cdp: CDP interface Policy name
    :param lldp: LLDP interface Policy name
    :param aaep: AAEP name

    """

    print("Defining Access Port Policy Group")
    print("... name : ", end='')
    prBlue(name)
    print("... Link Level Interface Policy : ", end='')
    prBlue(linkLevel)
    print("... CDP Interface Policy : ", end='')
    prBlue(cdp)
    print("... LLDP Interface Policy : ", end='')
    prBlue(lldp)
    print("... Associated AAEP : ", end='')
    prBlue(aaep)

    top_dn = cobra.mit.naming.Dn.fromString('uni/infra/funcprof/accportgrp-%s' % name)
    topMo = md.lookupByDn(top_dn.getParent())

    AccessPG = cobra.model.infra.AccPortGrp(topMo, name=name)
    cobra.model.infra.RsHIfPol(AccessPG, tnFabricHIfPolName=linkLevel)
    cobra.model.infra.RsCdpIfPol(AccessPG, tnCdpIfPolName=cdp)
    cobra.model.infra.RsLldpIfPol(AccessPG, tnLldpIfPolName=lldp)
    cobra.model.infra.RsAttEntP(AccessPG, tDn='uni/infra/attentp-%s' % aaep)
    push_to_apic(md,topMo)

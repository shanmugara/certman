import logging
import os
from subprocess import check_output, DEVNULL
import configparser
import yaml

from helpers.blp_logger import Blp_logger


class CertMan(object):
    def __init__(self, certfilename=None, keyfilename=None, days=6000, logdir="."):
        self.log = Blp_logger(logdir=logdir, logfile="certman.log")
        if not any([certfilename, keyfilename]):
            # auto detect ca file and key paths
            self.parsekubletcfg()
            self.parsemanifest()
            self.getcertfiles()
        else:
            self.currCert = certfilename
            self.currKey = keyfilename
        self.outfile = ""
        self.days = days
        self.cert_dir, self.cert_f = os.path.split(self.currCert)
        if not os.path.isfile(self.currCert):
            self.log.error("Cert file not found")
        if not os.path.isfile(self.currKey):
            self.log.error("Key file not found")

    def x509toreq(self):
        self.outfile = os.path.join(self.cert_dir, "new_"+self.cert_f+".req")
        cmd = f"openssl x509 -x509toreq -in {self.currCert} -signkey {self.currKey} -out {self.outfile}"
        cmd_out = self.run_subproc_cmd(cmd)
        if cmd_out:
            self.log.info(f"CSR generated and saved as {self.outfile}")

    def renewCert(self):
        new_cert = os.path.join(self.cert_dir, "new_"+self.cert_f)
        cmd = f"openssl x509 -req -days {self.days} -in {self.outfile} -signkey {self.currKey} -out {new_cert}"
        cmd_out = self.run_subproc_cmd(cmd)
        if cmd_out:
            self.log.info(f"New cert file saved as {new_cert}")

    def run_subproc_cmd(self, cmd):
        try:
            cmd_out = check_output([cmd], shell=True, stderr=DEVNULL).decode().strip()
            return cmd
        except Exception as e:
            self.log.error(f"Error while running cmd {e}")
            return False

    def parsekubletcfg(self):
        sys_unit = "/etc/systemd/system/kubelet.service.d/10-kubeadm.conf"
        kubeletcfg = ""
        try:
            with open(sys_unit) as f:
                lines = f.readlines()
                for line in lines:
                    if line.strip().startswith('Environment="KUBELET_CONFIG_ARGS'):
                        kubeletcfg = line.split("=")[-1].strip().strip('"')
                        break

            if kubeletcfg:
                with open(kubeletcfg) as f:
                    kubelet_dict = yaml.load(f, Loader=yaml.Loader)
                    self.staticpodpath = kubelet_dict['staticPodPath']
        except Exception as e:
            self.staticpodpath = ""
            self.log.error(f"Error parsing kubelet config - {e}")

    def parsemanifest(self, manifestfile="kube-controller-manager.yaml"):
        try:
            with open(os.path.join(self.staticpodpath, manifestfile)) as f:
                self.k_control_manifest = yaml.load(f, Loader=yaml.Loader)

        except Exception as e:
            self.log.error(f"error {e} while parsing kubernetes manifiest {manifestfile}")

    def getcertfiles(self):
        try:
            for i in self.k_control_manifest['spec']['containers'][0]['command']:
                if i.startswith("--cluster-signing-cert-file"):
                    _,cacert = i.split("=")
                    self.currCert = cacert
                elif i.startswith("--cluster-signing-key-file"):
                    _,key = i.split("=")
                    self.currKey = key

        except Exception as e:
            self.log.error(f"Error while getting cert file/key paths - {e}")






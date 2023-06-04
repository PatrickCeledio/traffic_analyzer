/*
   @Patrick Celedio
   Network traffic sniffer program written in C++
   Capture 802.3/DIX frames and displays source MAC, destination MAC,
   protocol, and payload data.
*/

#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>


// Define a frameio struct

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack

// Define Ethernet frame struct

struct ether_frame       // handy template for 802.3/DIX frames
{
   octet dst_mac[6];     // destination MAC address
   octet src_mac[6];     // source MAC address
   octet prot[2];        // protocol (or length)
   octet data[1500];     // payload
};

/*
 This thread sits around and receives frames from the network.
 When it gets one, it dispatches it to the proper protocol stack.
*/
void *protocol_loop(void *arg)
{
   // Init ether_frame struct called buf
   ether_frame buf;

   while(1)
   {
      printf("\n\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
      printf("\nStarting frame capture...\n");


      // Store size of frame in bytes into variable frame_size
      int frame_size = net.recv_frame(&buf,sizeof(buf));

      /*
         Minimum TCP header size = 20 bytes
         Minimum IPv4 header size = 20 bytes

         if-else block checks size of frame; denies frame < 42 bytes
      */
      if ( frame_size < 42 ) {
         printf("Skipping frame: Frame size (%d bytes) is less than 42 bytes. \n", frame_size);
         continue; //   bad frame!
      }else{
         printf("\nAnalyzing frame: Total size %d bytes\n\n", frame_size);
      }

      /*
      @Patrick Celedio
      Display eth_frame details
      */
      // printf("buf.dst_mac is: %02x\n", buf.dst_mac);
      // printf("buf.src_mac is: %02x\n", buf.src_mac);
      // printf("buf.prot is: \n");
      printf("buf.dst_mac is: \n");
      for (int i=0; i<6; i++){
         printf("%02x", buf.dst_mac[i]);
         // Add spacing in between data
        if(i%2==0){
            printf(" ");
        }

      }
      printf("\n");

      printf("buf.src_mac is: \n");
      for (int i=0; i<6; i++){
         printf("%02x", buf.src_mac[i]);
         // Add spacing in between data
        if(i%2==0){
            printf(" ");
        }

      }
      printf("\n");

      printf("buf.prot is: \n");
      for (int i=0; i<2; i++){
         printf("%02x", buf.prot[i]);
         // Add spacing in between data
        if(i%2==0){
            printf(" ");
        }

      }
      printf("\n");

    printf("First 30 bits of buf.data is: \n");
    for (int i=0; i<30; i++){
        printf("%02x", buf.data[i]);

        // Add spacing in between data
        if(i%2==0){
            printf(" ");
        }

        // When 22 bits of data has elapsed
        if(i == 9){
            // printf("\n i==9 Printing space\n");
            printf(" ");
        } 

        // When 42 bits of data has elapsed
        if(i==29){
            // printf("\n i==29 Printing space\n");
            printf(" ");
        }
    }
    printf("\n");

      // Checks frame if it is either arp or ip
      switch ( buf.prot[0]<<8 | buf.prot[1] )
      {
         // Sends payload data to to function
          case 0x800:
            ip_queue.send(PACKET,buf.data, frame_size);
            // ip_queue.send(PACKET,buf.data,n);
            break;
          case 0x806:
            arp_queue.send(PACKET,buf.data, frame_size);
            break;
      }
   }
}

//
// Toy function to print something interesting when an IP frame arrives
//
void *ip_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;
   int timer_no = 1;

   // for fun, fire a timer each time we get a frame
   int counter = 0;
   while ( 1 )
   {

      ip_queue.recv(&event, buf, sizeof(buf));
      if ( event != TIMER )
      {
         
         printf("\n");

         printf("Recieved IP frame from %d.%d.%d.%d, queued timer %d\n",
                  buf[12],buf[13],buf[14],buf[15],timer_no);
         ip_queue.timer(10,timer_no);
         timer_no++;


        printf("First 30 bits of buf.data is: \n");
        for (int i=0; i<30; i++){
            printf("%02x", buf[i]);

            // Add spacing in between data
            if(i%2==0){
                printf(" ");
            }

            // When 22 bits of data has elapsed
            if(i == 9){
                // printf("\n i==9 Printing space\n");
                printf(" ");
            } 

            // When 42 bits of data has elapsed
            if(i==29){
                // printf("\n i==29 Printing space\n");
                printf(" ");
            }
         }
         printf("\n\n");
      }
      else
      {
         // printf("\ntimer %d fired\n",*(int *)buf);
      }

   }
}

//
// Toy function to print something interesting when an ARP frame arrives
//
void *arp_protocol_loop(void *arg)
{
   octet buf[1500];
   event_kind event;

   while ( 1 )
   {
    arp_queue.recv(&event, buf, sizeof(buf));
    printf("Recieved ARP %s\n", buf[7]==1? "request":"reply");
    printf("\n!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
   }
}

//
// if you're going to have pthreads, you'll need some thread descriptors
//
pthread_t loop_thread, arp_thread, ip_thread;

//
// start all the threads then step back and watch (actually, the timer
// thread will be started later, but that is invisible to us.)
//
int main()
{
   printf("App starting.\n");
   
   /*
      @Patrick Celedio
      Changed from "eth1" to "eth0"
      Gain access to network adapter and capture packets 
   */
   net.open_net("eth0");

   // Three threads are created for each function
   pthread_create(&loop_thread,NULL,protocol_loop,NULL);
   pthread_create(&arp_thread,NULL,arp_protocol_loop,NULL);
   pthread_create(&ip_thread,NULL,ip_protocol_loop,NULL);
   for ( ; ; )
      sleep(1);

   
}


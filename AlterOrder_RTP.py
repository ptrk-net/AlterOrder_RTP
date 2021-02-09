import sys
import re
import queue
import copy
import fnfqueue

# GLOBAL VARIABLES

# Iptables nfqueue
NFQUEUE = 1

# RTP type of PDU
RTP_AUDIO = 124
RTP_VIDEO = 103
RTP_END = 0


def receiver(verbose, covert_channel):
  # to control the packets
  old_packet = None
  counter_packets = 0
  total_packets = 0

  # to control the length of the message to hide
  secret_message = ''
  first_time = True
  message_finished = False

  # Iptables queue connection
  try:
    queue = 1
    conn = fnfqueue.Connection()
    q = conn.bind(queue)
    q.set_mode(0xffff, fnfqueue.COPY_PACKET)
  except PermissionError:
    print('Are you sure you\'re root or NFQueue is not in use? Exit..')
    exit()

  if covert_channel:
    while True:
      try:
        for act_packet in conn:
          act_type = int.from_bytes(act_packet.payload[29:30], byteorder='big')
          if act_type == RTP_AUDIO or act_type == RTP_VIDEO or not message_finished:
            total_packets += 1
            if old_packet is None:
              old_packet = copy.copy(act_packet)
            else:
              old_type = int.from_bytes(old_packet.payload[29:30], byteorder='big')
              old_seq = int.from_bytes(old_packet.payload[30:32], byteorder='big')

              old_packet.mangle()
              old_packet = copy.copy(act_packet)
              counter_packets += 1
              if verbose == 2:
                print('     * type: {} | seq: {} | counter: {}'.format(old_type,
                                                                       old_seq,
                                                                       counter_packets))

              if act_type != old_type:
                if verbose >= 1:
                  print('- x: {} | type: {} | seq: {} | counter: {}'.format((counter_packets % 2),
                                                                            old_type,
                                                                            old_seq,
                                                                            counter_packets))
                secret_message += str(counter_packets % 2)
                counter_packets = 0
                if (first_time and len(secret_message) == 7) or (
                  not first_time and len(secret_message) == 8):
                  try:
                    secret_message = int(secret_message, 2)
                    secret_message = secret_message.to_bytes((secret_message.bit_length() + 7) // 8,
                                                             'big').decode()
                    if verbose == 0:
                      sys.stdout.write(str(secret_message))
                      sys.stdout.flush()
                    else:
                      print('+++++++++++++++++++++++++++++++++++++++++++++++ {}'.format(str(secret_message)))
                    secret_message = ''
                    first_time = False
                  except UnicodeDecodeError:
                    if verbose == 0:
                      sys.stdout.write('-UE-')
                      sys.stdout.flush()
                    else:
                      print('+++++++++++++++++++++++++++++++++++++++++++++++ -UE-')
                    secret_message = ''
                    first_time = False
                  except TypeError:
                    if verbose == 0:
                      sys.stdout.write('-TE-')
                      sys.stdout.flush()
                    else:
                      print('+++++++++++++++++++++++++++++++++++++++++++++++ -TE-')
                    secret_message = ''
                    first_time = False
          elif act_type == 0:
            message_finished = True
          else:
            act_packet.mangle()
      except KeyboardInterrupt:
        conn.close()
        print('bye, bye!')
        exit()
      except:
        pass
  else:
    try:
      for act_packet in conn:
        act_packet.mangle()
    except:
      exc_type, exc_obj, exc_tb = sys.exc_info()
      print('exception: {}: {}'.format(exc_type, exc_tb.tb_lineno))


def sender(verbose, covert_channel, secret_message):
  # to control the packets
  old_packet = None
  exc_audios = queue.Queue()
  exc_videos = queue.Queue()
  counter_packets = 0
  type_sending = 0

  # to control the length of the message to hide
  counter_bits = 0

  # Iptables queue connection
  try:
    conn = fnfqueue.Connection()
    q = conn.bind(NFQUEUE)
    q.set_mode(0xffff, fnfqueue.COPY_PACKET)
  except PermissionError:
    print('Are you sure you\'re root or NFQueue is not in use? Exit..')
    exit()

  if verbose == 2:
    print('------ SECRET MESSAGE PARITY: {}'.format(secret_message))

  if covert_channel:
    while counter_bits < len(secret_message):
      try:
        for act_packet in conn:
          act_type = int.from_bytes(act_packet.payload[29:30], byteorder='big')
          if act_type == RTP_AUDIO or act_type == RTP_VIDEO:
            if old_packet is None:
              old_packet = copy.copy(act_packet)
              type_sending = int.from_bytes(old_packet.payload[29:30], byteorder='big')
            else:
              old_type = int.from_bytes(old_packet.payload[29:30], byteorder='big')
              old_seq = int.from_bytes(old_packet.payload[30:32], byteorder='big')

              if act_type == old_type and old_type == type_sending:
                counter_packets += 1
                if verbose == 2:
                  print('   > sending because equals')
                  print('     ---- sending type: {} | seq: {} | counter: {}'.format(old_type,
                                                                                    old_seq,
                                                                                    counter_packets))
                old_packet.mangle()
                old_packet = copy.copy(act_packet)
              elif act_type != old_type and old_type == type_sending:
                parity = ((counter_packets + 1) % 2 == int(secret_message[counter_bits]))
                if parity:
                  old_packet.mangle()
                  old_packet = copy.copy(act_packet)
                  if verbose == 2:
                    print('   > sending old because of parity')
                  if verbose >= 1:
                    print('- x: {} | type: {} | seq: {} | counter: {}'.format((counter_packets + 1) % 2,
                                                                              old_type,
                                                                              old_seq,
                                                                              (counter_packets + 1)))
                  counter_packets = 0
                  counter_bits += 1
                  type_sending = act_type
                elif counter_packets == 0:
                  if verbose == 2:
                    print('   > sending old because must be sent one of this type')
                    print('      ---- sending type: {} | seq: {} | counter: {}'.format(old_type,
                                                                                       old_seq,
                                                                                       (counter_packets + 1)
                                                                                       ))
                  old_packet.mangle()
                  old_packet = copy.copy(act_packet)
                  counter_packets += 1
                else:
                  if verbose == 2:
                    print('   * NOT sending old packet because of parity: {}'.format(type_sending))
                  if verbose >= 1:
                    print('- x: {} | type: {} | seq: {} | counter: {}'.format(counter_packets % 2,
                                                                              old_type,
                                                                              old_seq,
                                                                              counter_packets))
                  if old_type == RTP_AUDIO:
                    exc_audios.put(old_packet)
                  else:
                    exc_videos.put(old_packet)
                  old_packet = copy.copy(act_packet)
                  counter_packets = 0
                  counter_bits += 1
                  type_sending = act_type

                if not exc_audios.empty() and act_type == RTP_AUDIO:
                  if verbose == 2:
                    print('   + sending excedeed audio packets')
                  counter_packets = 0
                  while not exc_audios.empty():
                    exc_packet = exc_audios.get()
                    exc_seq = int.from_bytes(exc_packet.payload[30:32], byteorder='big')
                    exc_packet.mangle()
                    counter_packets += 1
                    if verbose == 2:
                      print('      ---- sending type: {} | seq: {} | counter: {}'.format(act_type,
                                                                                         exc_seq,
                                                                                         counter_packets))
                if not exc_videos.empty() and act_type == RTP_VIDEO:
                  if verbose == 2:
                    print('   + sending excedeed video packets')
                  counter_packets = 0
                  while not exc_videos.empty():
                    exc_packet = exc_videos.get()
                    exc_seq = int.from_bytes(exc_packet.payload[30:32], byteorder='big')
                    exc_packet.mangle()
                    counter_packets += 1
                    if verbose == 2:
                      print('      ---- sending type: {} | seq: {} | counter: {}'.format(act_type,
                                                                                         exc_seq,
                                                                                         counter_packets))

              elif old_type != type_sending:
                if verbose == 2:
                  print('   * NOT sending because not same type that should be sending: {}'.format(type_sending))
                if old_type == RTP_AUDIO:
                  exc_audios.put(old_packet)
                else:
                  exc_videos.put(old_packet)
                old_packet = copy.copy(act_packet)
          else:
            act_packet.mangle()
      except KeyboardInterrupt:
        conn.close()
        print('bye, bye!')
        exit()
      except IndexError:
        pass
      except:
        exc_type, exc_obj, exc_tb = sys.exc_info()
        print('exception: {}: {}'.format(exc_type, exc_tb.tb_lineno))

    old_packet.payload = old_packet.payload[:29] + bytes([RTP_END]) + old_packet.payload[30:]
    old_packet.mangle()
    print('Missatge enviat')
    try:
      # To continue with the videocall
      for act_packet in conn:
        act_packet.mangle()
    except:
      exc_type, exc_obj, exc_tb = sys.exc_info()
      print('exception: {}: {}'.format(exc_type, exc_tb.tb_lineno))
  else:
    try:
      for act_packet in conn:
        act_packet.mangle()
    except:
      exc_type, exc_obj, exc_tb = sys.exc_info()
      print('exception: {}: {}'.format(exc_type, exc_tb.tb_lineno))


# ---
# argv_error function
# ---
# Print the argument parsing error
def argv_error():
  print('ERROR: arguments:')
  print('./AlterOrder_RTP.py [-v|-d] (decoder|encoder (ncc|cc [\'Message\'|-t file_name]))')
  sys.exit()


# ---
# Main function
# ---
# Based on the arguments, decide if the program should be the encoder or decoder
if __name__ == '__main__':
  if len(sys.argv) < 2 or len(sys.argv) > 5:
    argv_error()

  covert_channel = False
  secret_message = ''

  more = 1
  verbose = 0
  if sys.argv[1] == '-v':
    verbose = 1
  elif sys.argv[1] == '-d':
    verbose = 2
  else:
    more = 0

  if sys.argv[2 + more] == 'cc':
    covert_channel = True
  elif sys.argv[2 + more] != 'ncc':
    argv_error()

  if sys.argv[1 + more] == 'encoder':
    if covert_channel:
      string = sys.argv[3 + more]
      if string == '-t':
        f = open(sys.argv[4 + more], 'r')
        string = f.read()
        f.close()
      secret_message = bin(int.from_bytes(string.encode(), 'big'))
      secret_message = re.sub('^..', '', secret_message)
    sender(verbose, covert_channel, secret_message)
  elif sys.argv[1 + more] == 'decoder':
    receiver(verbose, covert_channel)
  else:
    argv_error()


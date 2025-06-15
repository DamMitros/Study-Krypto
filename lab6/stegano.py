# Damian Mitros index: 292586
# Kryptografia - Steganografia
import sys, re, argparse

class HTMLSteganography:
  def __init__(self):
    pass
    
  def hex_to_bits(self, hex_string):
    hex_string = hex_string.strip().replace(' ', '').replace('\n', '')
    bits = ''
    for char in hex_string:
      if char.lower() in '0123456789abcdef':
        bits += format(int(char, 16), '04b')
      else:
        raise ValueError(f"Nieprawidłowy znak hex: '{char}'. Dozwolone znaki: [0-9,a-f]")
    return bits
  
  def bits_to_hex(self, bits):
    while len(bits) % 4 != 0:
      bits += '0'
    
    hex_chars = []
    for i in range(0, len(bits), 4):
      nibble = bits[i:i+4]
      hex_chars.append(format(int(nibble, 2), 'x'))
    
    return ''.join(hex_chars)

  def embed_method1(self, html_content, message_bits):
    lines = html_content.split('\n')
    cleaned_lines = [line.rstrip() for line in lines]
    
    if len(message_bits) > len(cleaned_lines):
      raise ValueError(f"Nośnik za mały! Wiadomość ma {len(message_bits)} bitów, dostępne wiersze: {len(cleaned_lines)}")
      
    for i, bit in enumerate(message_bits):
      if bit == '1':
        cleaned_lines[i] += ' '
    
    return '\n'.join(cleaned_lines)
  
  def extract_method1(self, html_content):
    lines = html_content.split('\n')
    bits = ''
    
    for line in lines:
      if line.endswith(' '):
        bits += '1'
      else:
        bits += '0'
    
    return bits

  def embed_method2(self, html_content, message_bits):
    content = re.sub(r'  +', ' ', html_content)
    
    single_spaces = []
    for i, char in enumerate(content):
      if char == ' ':
        prev_char = content[i-1] if i > 0 else ''
        next_char = content[i+1] if i < len(content)-1 else ''
        
        if prev_char != '\n' and prev_char != '\t' and prev_char != ' ':
          single_spaces.append(i)
    
    if len(message_bits) > len(single_spaces):
      raise ValueError(f"Nośnik za mały! Wiadomość ma {len(message_bits)} bitów, dostępne spacje: {len(single_spaces)}")
    
    content_list = list(content)
    
    for i in range(len(message_bits)-1, -1, -1):
      space_pos = single_spaces[i]
      if message_bits[i] == '1':
        content_list[space_pos] = '  '
    
    return ''.join(content_list)
  
  def extract_method2(self, html_content):
    bits = ''
    i = 0
    
    while i < len(html_content):
      if html_content[i] == ' ':
        if i + 1 < len(html_content) and html_content[i + 1] == ' ':
          bits += '1'
          i += 2
        else:
          prev_char = html_content[i-1] if i > 0 else ''
          if prev_char != '\n' and prev_char != '\t':
            bits += '0'
          i += 1
      else:
        i += 1
    
    return bits

  def embed_method3(self, html_content, message_bits):
    content = re.sub(r'margin-botom[^;\\"\\s]*[;\\"]?', '', html_content, flags=re.IGNORECASE)
    content = re.sub(r'lineheight[^;\\"\\s]*[;\\"]?', '', content, flags=re.IGNORECASE)
    content = re.sub(r'style="\\s*"', '', content)
    content = re.sub(r'style=\\\'\\\'', '', content)
    
    all_p_tags_matches = list(re.finditer(r'<p(?:\\s[^>]*)?>', content, re.IGNORECASE))
    
    suitable_p_tags = []
    for match in all_p_tags_matches:
      tag_outer_html = match.group(0)
      style_attr_match = re.search(r'style\\s*=\\s*["\\\']([^"\\\']*)["\\\']', tag_outer_html, re.IGNORECASE)
      has_forbidden_style = False
      if style_attr_match:
        style_content_val = style_attr_match.group(1).lower()
        if 'margin-bottom:' in style_content_val or 'line-height:' in style_content_val:
          has_forbidden_style = True
      
      if not has_forbidden_style:
        suitable_p_tags.append(match)

    if len(message_bits) > len(suitable_p_tags):
      raise ValueError(f"Nośnik za mały! Wiadomość ma {len(message_bits)} bitów, dostępne odpowiednie tagi <p>: {len(suitable_p_tags)}")

    offset = 0
    for i, bit in enumerate(message_bits):
      if i >= len(suitable_p_tags):
        break
        
      match = suitable_p_tags[i]
      tag_start = match.start() + offset
      tag_end = match.end() + offset
      tag_content = content[tag_start:tag_end]

      if bit == '0':
        error_attr = 'margin-botom: 0cm'
      else:
        error_attr = 'lineheight: 100%'

      if re.search(r'style\s*=\s*["\']', tag_content, re.IGNORECASE):
        style_match = re.search(r'style\s*=\s*["\']([^"\']*)["\']', tag_content, re.IGNORECASE)
        if style_match:
          style_value = style_match.group(1)
          if style_value and not style_value.endswith(';'):
            new_style_value = style_value + '; ' + error_attr
          else:
            new_style_value = style_value + error_attr
          new_tag = tag_content.replace(style_match.group(0), f'style="{new_style_value}"')
        else:
          new_tag = tag_content
      else:
        new_tag = tag_content[:-1] + f' style="{error_attr}">'
      
      content = content[:tag_start] + new_tag + content[tag_end:]
      offset += len(new_tag) - len(tag_content)
    
    return content
  
  def extract_method3(self, html_content):
    bits = ''
    
    margin_matches = [(match.start(), '0') for match in re.finditer(r'margin-botom', html_content, re.IGNORECASE)]
    lineheight_matches = [(match.start(), '1') for match in re.finditer(r'lineheight', html_content, re.IGNORECASE)]
    
    all_matches = margin_matches + lineheight_matches
    all_matches.sort()
    
    for _, bit in all_matches:
      bits += bit
    
    return bits

  def embed_method4(self, html_content, message_bits):
    content = re.sub(r'<font[^>]*></font>', '', html_content, flags=re.IGNORECASE)
    content = re.sub(r'</font><font[^>]*>', '', content, flags=re.IGNORECASE)
    
    font_tags = list(re.finditer(r'<font[^>]*>', content, re.IGNORECASE))
    
    if len(message_bits) > len(font_tags):
      raise ValueError(f"Nośnik za mały! Wiadomość ma {len(message_bits)} bitów, dostępne tagi FONT: {len(font_tags)}")
    
    offset = 0
    for i, bit in enumerate(message_bits):
      if i >= len(font_tags):
        break
        
      match = font_tags[i]
      tag_end = match.end() + offset
      font_tag = match.group()
      
      if bit == '1':
        insertion = f'</font>{font_tag}'
        content = content[:tag_end] + insertion + content[tag_end:]
        offset += len(insertion)
      else:
        close_pos = content.find('</font>', tag_end)
        if close_pos != -1:
          close_end = close_pos + 7
          insertion = f'{font_tag}</font>'
          content = content[:close_end] + insertion + content[close_end:]
          offset += len(insertion)
    
    return content
  
  def extract_method4(self, html_content):
    bits = ''
    
    pattern1 = re.compile(r'</font><font[^>]*>', re.IGNORECASE)
    pattern0 = re.compile(r'</font><font[^>]*></font>', re.IGNORECASE)

    matches1 = [(match.start(), '1') for match in pattern1.finditer(html_content)]
    matches0 = [(match.start(), '0') for match in pattern0.finditer(html_content)]

    filtered_matches1 = []
    for pos1, bit1 in matches1:
      is_part_of_pattern0 = False
      for pos0, bit0 in matches0:
        if pos1 == pos0:
          is_part_of_pattern0 = True
          break
      if not is_part_of_pattern0:
        filtered_matches1.append((pos1, bit1))

    all_matches = filtered_matches1 + matches0
    all_matches.sort()
    
    for _, bit in all_matches:
      bits += bit
    
    return bits

  def embed_message(self, html_file, message_file, output_file, method):
    try:
      with open(html_file, 'r', encoding='utf-8') as f:
        html_content = f.read()
      
      with open(message_file, 'r', encoding='utf-8') as f:
        message_hex = f.read().strip()

      message_payload_bits = self.hex_to_bits(message_hex)
      
      if not message_payload_bits:
        raise ValueError("Pusta wiadomość lub nieprawidłowy format hex")

      original_message_length = len(message_payload_bits)
      length_bits = format(original_message_length, '016b')
      message_bits_to_embed = length_bits + message_payload_bits
      
      if method == 1:
        result = self.embed_method1(html_content, message_bits_to_embed)
      elif method == 2:
        result = self.embed_method2(html_content, message_bits_to_embed)
      elif method == 3:
        result = self.embed_method3(html_content, message_bits_to_embed)
      elif method == 4:
        result = self.embed_method4(html_content, message_bits_to_embed)
      else:
        raise ValueError(f"Nieznana metoda: {method}")
      
      with open(output_file, 'w', encoding='utf-8') as f:
        f.write(result)
        
      print(f"Wiadomość zanurzona pomyślnie w {output_file}")
      print(f"Użyta metoda: {method}")
      print(f"Długość oryginalnej wiadomości: {original_message_length} bitów")
      print(f"Całkowita długość zanurzonych danych (z długością): {len(message_bits_to_embed)} bitów")
      
    except Exception as e:
      print(f"Błąd podczas zanurzania: {e}")
      sys.exit(1)
  
  def extract_message(self, watermark_file, output_file, method):
    try:
      with open(watermark_file, 'r', encoding='utf-8') as f:
        html_content = f.read()

      if method == 1:
        extracted_total_bits = self.extract_method1(html_content)
      elif method == 2:
        extracted_total_bits = self.extract_method2(html_content)
      elif method == 3:
        extracted_total_bits = self.extract_method3(html_content)
      elif method == 4:
        extracted_total_bits = self.extract_method4(html_content)
      else:
        raise ValueError(f"Nieznana metoda: {method}")
      
      if len(extracted_total_bits) < 16:
        raise ValueError("Nie znaleziono wystarczająco bitów do odczytania długości wiadomości.")

      length_bits_str = extracted_total_bits[:16]
      actual_message_length = int(length_bits_str, 2)
      
      expected_total_bits_from_prefix = 16 + actual_message_length
      
      if len(extracted_total_bits) < expected_total_bits_from_prefix:
        print(f"Ostrzeżenie: Wyodrębniono {len(extracted_total_bits)} bitów, ale oczekiwano {expected_total_bits_from_prefix} bitów na podstawie odczytanej długości.")

      message_payload_bits = extracted_total_bits[16:expected_total_bits_from_prefix]

      if len(message_payload_bits) < actual_message_length:
         raise ValueError(f"Niekompletna wiadomość: oczekiwano {actual_message_length} bitów ładunku, odzyskano {len(message_payload_bits)}.")

      message_hex = self.bits_to_hex(message_payload_bits)
      
      with open(output_file, 'w', encoding='utf-8') as f:
        f.write(message_hex)
      
      print(f"Wiadomość wyodrębniona pomyślnie do {output_file}")
      print(f"Użyta metoda: {method}, Odczytana długość wiadomości: {actual_message_length} bitów")
      
    except Exception as e:
      print(f"Błąd podczas wyodrębniania: {e}")
      sys.exit(1)

def main():
  parser = argparse.ArgumentParser(description='Program steganografii HTML')
  parser.add_argument('-e', '--embed', action='store_true', help='Zanurz wiadomość')
  parser.add_argument('-d', '--detect', action='store_true', help='Wyodrębnij wiadomość')
  parser.add_argument('-1', '--method1', action='store_true', help='Metoda 1: spacje na końcu wierszy')
  parser.add_argument('-2', '--method2', action='store_true', help='Metoda 2: pojedyncze/podwójne spacje')
  parser.add_argument('-3', '--method3', action='store_true', help='Metoda 3: błędne nazwy atrybutów')
  parser.add_argument('-4', '--method4', action='store_true', help='Metoda 4: puste pary znaczników FONT')
  
  args = parser.parse_args()
  
  if not (args.embed or args.detect):
    print("Błąd: Musisz wybrać -e (embed) lub -d (detect)")
    sys.exit(1)
  
  if args.embed and args.detect:
    print("Błąd: Nie można wybrać jednocześnie -e i -d")
    sys.exit(1)
  
  method = None
  if args.method1:
    method = 1
  elif args.method2:
    method = 2
  elif args.method3:
    method = 3
  elif args.method4:
    method = 4
  else:
    print("Błąd: Musisz wybrać metodę (-1, -2, -3, lub -4)")
    sys.exit(1)
  
  stego = HTMLSteganography()
  
  if args.embed:
    stego.embed_message('cover.html', 'mess.txt', 'watermark.html', method)
  else:
    stego.extract_message('watermark.html', 'detect.txt', method)

if __name__ == '__main__':
  main()
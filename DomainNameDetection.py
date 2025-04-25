import whois
import dns.resolver
import socket
import requests
from datetime import datetime
from colorama import Fore, Style, init
import time

# 初始化colorama
init(autoreset=True)

class DomainDetector:
    def __init__(self):
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    def format_date(self, date_value):
        """格式化日期显示"""
        try:
            if not date_value:
                return '未知'
            
            # 如果是列表，取最早的日期
            if isinstance(date_value, list):
                valid_dates = [d for d in date_value if d]
                if not valid_dates:
                    return '未知'
                date_value = min(valid_dates)  # 取最早的日期
        
            # 如果是datetime对象，格式化显示
            if isinstance(date_value, datetime):
                return date_value.strftime('%Y-%m-%d')  # 只显示日期部分
            
            return str(date_value)
        except Exception as e:
            return f'未知 ({str(e)})'

    def format_status(self, status):
        """格式化状态信息显示"""
        try:
            if not status:
                return '未知'
            
            if isinstance(status, list):
                # 去重并只保留状态名称，不要URL部分
                unique_statuses = set()
                for s in status:
                    # 分割字符串，取第一部分（状态名称）
                    status_name = s.split('https://')[0].strip()
                    status_name = status_name.split('(')[0].strip()  # 移除括号部分
                    if status_name:
                        unique_statuses.add(status_name)
                return '\n    '.join(sorted(unique_statuses))
            
            return str(status)
        except Exception:
            return '未知'

    def format_nameservers(self, nameservers):
        """格式化域名服务器显示"""
        try:
            if not nameservers:
                return '未知'
            
            if isinstance(nameservers, list):
                # 去重并转换为小写
                unique_ns = sorted(set(ns.lower() for ns in nameservers))
                return '\n    '.join(unique_ns)
            
            return str(nameservers).lower()
        except Exception:
            return '未知'

    def get_whois_info(self, domain):
        """获取域名的WHOIS信息"""
        try:
            # 获取WHOIS信息
            w = whois.whois(domain)
            if not w or not w.domain_name:
                return {'error': '无法获取WHOIS信息'}

            # 直接打印原始数据，用于调试
            # print(f"\n调试信息: {w}")

            # 处理注册商
            registrar = '未知'
            if hasattr(w, 'registrar') and w.registrar:
                registrar = w.registrar[0] if isinstance(w.registrar, list) else w.registrar

            # 处理日期的辅助函数
            def parse_date(date_value):
                """解析日期，处理时区问题"""
                if not date_value:
                    return None
                if isinstance(date_value, list):
                    # 过滤掉None值
                    dates = [d for d in date_value if d]
                    if not dates:
                        return None
                    # 取第一个日期
                    date_value = dates[0]
                try:
                    if isinstance(date_value, datetime):
                        return date_value.strftime('%Y-%m-%d')
                    return str(date_value).split()[0]  # 只取日期部分
                except:
                    return '未知'

            # 处理各种日期
            creation_date = parse_date(w.creation_date)
            expiration_date = parse_date(w.expiration_date)
            updated_date = parse_date(w.updated_date)

            # 处理状态
            status = set()
            if hasattr(w, 'status') and w.status:
                if isinstance(w.status, list):
                    for s in w.status:
                        if s:
                            # 只保留状态码部分，去除URL和括号
                            s = str(s).split('https://')[0].strip()
                            s = s.split('(')[0].strip()
                            if s:
                                status.add(s)
                else:
                    s = str(w.status).split('https://')[0].strip()
                    s = s.split('(')[0].strip()
                    if s:
                        status.add(s)

            # 处理域名服务器
            nameservers = set()
            if hasattr(w, 'name_servers') and w.name_servers:
                if isinstance(w.name_servers, list):
                    nameservers = {ns.lower() for ns in w.name_servers if ns}
                else:
                    nameservers = {w.name_servers.lower()}

            return {
                'registrar': registrar,
                'creation_date': creation_date or '未知',
                'expiration_date': expiration_date or '未知',
                'last_updated': updated_date or '未知',
                'status': '\n    '.join(sorted(status)) if status else '未知',
                'name_servers': '\n    '.join(sorted(nameservers)) if nameservers else '未知'
            }

        except Exception as e:
            print(f"\n调试错误: {str(e)}")  # 添加错误调试信息
            return {'error': f'WHOIS查询失败: {str(e)}'}

    def get_dns_records(self, domain):
        """获取域名的DNS记录"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(answer) for answer in answers]
            except Exception:
                continue
        
        return records

    def check_ssl(self, domain):
        """检查域名的SSL证书状态"""
        try:
            response = requests.get(f'https://{domain}', timeout=5, verify=True)
            return {'status': 'Valid SSL', 'code': response.status_code}
        except requests.exceptions.SSLError:
            return {'status': 'Invalid SSL', 'code': None}
        except requests.exceptions.ConnectionError as e:
            if 'NameResolutionError' in str(e):
                return {'status': '域名无法解析', 'code': None}
            elif 'Connection refused' in str(e):
                return {'status': '连接被拒绝', 'code': None}
            else:
                return {'status': '连接错误', 'code': None}
        except requests.exceptions.Timeout:
            return {'status': '连接超时', 'code': None}
        except Exception as e:
            return {'status': f'检查失败', 'code': None}

    def get_main_domain(self, domain):
        """提取主域名（去除www前缀）"""
        if domain.startswith('www.'):
            return domain[4:]
        return domain

    def analyze_domain(self, domain):
        """分析域名的所有信息"""
        print(f"\n{Fore.CYAN}正在检测域名: {domain}{Style.RESET_ALL}")
        
        # 获取主域名用于WHOIS查询
        main_domain = self.get_main_domain(domain)
        
        print("获取WHOIS信息...")
        whois_info = self.get_whois_info(main_domain)  # 使用主域名查询WHOIS
        
        print("获取DNS记录...")
        dns_records = self.get_dns_records(domain)  # 使用原始域名查询DNS
        
        print("检查SSL状态...")
        ssl_info = self.check_ssl(domain)  # 使用原始域名检查SSL

        return {
            'domain': domain,
            'main_domain': main_domain,
            'whois': whois_info,
            'dns': dns_records,
            'ssl': ssl_info
        }

    def display_results(self, result):
        """显示检测结果"""
        print("\n" + "=" * 50)
        print(f"{Fore.CYAN}域名检测报告{Style.RESET_ALL}")
        print("=" * 50)
        
        print(f"\n检测域名: {result['domain']}")
        if result['domain'] != result['main_domain']:
            print(f"主域名: {result['main_domain']}")
        print("-" * 30)
        
        # WHOIS信息
        print(f"\n{Fore.CYAN}WHOIS信息:{Style.RESET_ALL}")
        if 'error' in result['whois']:
            print(f"  {Fore.RED}错误: {result['whois']['error']}{Style.RESET_ALL}")
        else:
            whois_info = result['whois']
            print(f"  注册商: {whois_info['registrar']}")
            print(f"  创建时间: {whois_info['creation_date']}")
            print(f"  到期时间: {whois_info['expiration_date']}")
            print(f"  最后更新: {whois_info['last_updated']}")
            if whois_info['status'] != '未知':
                print(f"  状态: \n    {whois_info['status']}")
            else:
                print(f"  状态: {whois_info['status']}")
            if whois_info['name_servers'] != '未知':
                print(f"  域名服务器: \n    {whois_info['name_servers']}")
            else:
                print(f"  域名服务器: {whois_info['name_servers']}")
        
        # DNS记录
        print(f"\n{Fore.CYAN}DNS记录:{Style.RESET_ALL}")
        if result['dns']:
            for record_type, records in result['dns'].items():
                print(f"  {record_type}记录:")
                for record in records:
                    print(f"    - {record}")
        else:
            print(f"  {Fore.YELLOW}未找到DNS记录{Style.RESET_ALL}")
        
        # SSL状态
        print(f"\n{Fore.CYAN}SSL状态:{Style.RESET_ALL}")
        ssl_status = result['ssl']['status']
        if ssl_status == 'Valid SSL':
            print(f"  {Fore.GREEN}{ssl_status}{Style.RESET_ALL}")
        elif ssl_status in ['域名无法解析', '连接被拒绝', '连接超时', '连接错误', '检查失败']:
            print(f"  {Fore.YELLOW}{ssl_status}{Style.RESET_ALL}")
        else:
            print(f"  {Fore.RED}{ssl_status}{Style.RESET_ALL}")
        if result['ssl']['code']:
            print(f"  HTTP状态码: {result['ssl']['code']}")

    def extract_domain_from_url(self, url):
        """从URL中提取域名"""
        try:
            # 移除协议部分
            if '://' in url:
                url = url.split('://', 1)[1]
            
            # 移除路径、查询参数和锚点
            url = url.split('/')[0]
            url = url.split('?')[0]
            url = url.split('#')[0]
            
            # 移除端口号
            if ':' in url:
                url = url.split(':')[0]
            
            # 移除用户名和密码部分
            if '@' in url:
                url = url.split('@')[1]
            
            return url.strip().lower()
        except Exception:
            return None

    def run(self):
        """运行域名检测工具"""
        try:
            print(f"{Fore.CYAN}域名信息检测工具{Style.RESET_ALL}")
            print("输入 'exit' 退出程序")
            print("支持直接输入URL，将自动提取域名\n")

            while True:
                try:
                    user_input = input("\n请输入域名或URL: ").strip().lower()
                    
                    if user_input == 'exit':
                        print("程序退出")
                        break
                    
                    if not user_input:
                        print(f"{Fore.RED}输入不能为空{Style.RESET_ALL}")
                        continue

                    # 从输入中提取域名
                    domain = self.extract_domain_from_url(user_input)
                    if not domain:
                        print(f"{Fore.RED}无法从输入中提取有效域名{Style.RESET_ALL}")
                        continue

                    # 验证域名格式
                    if not self.is_valid_domain(domain):
                        print(f"{Fore.RED}无效的域名格式{Style.RESET_ALL}")
                        continue

                    # 如果输入的是URL，显示提取的域名
                    if domain != user_input:
                        print(f"{Fore.YELLOW}从URL中提取的域名: {domain}{Style.RESET_ALL}")

                    start_time = time.time()
                    result = self.analyze_domain(domain)
                    self.display_results(result)
                    end_time = time.time()
                    print(f"\n检测耗时: {end_time - start_time:.2f}秒")

                except KeyboardInterrupt:
                    print("\n程序被用户中断")
                    break
                except Exception as e:
                    print(f"{Fore.RED}检测出错: {str(e)}{Style.RESET_ALL}")
                    continue

        except KeyboardInterrupt:
            print("\n程序被用户中断")
        except Exception as e:
            print(f"{Fore.RED}程序运行错误: {str(e)}{Style.RESET_ALL}")
        finally:
            print("\n感谢使用域名检测工具")

    def is_valid_domain(self, domain):
        """验证域名格式"""
        if not domain:
            return False
        
        # 基本域名格式验证
        if len(domain) > 255:
            return False
        
        # 检查域名部分
        parts = domain.split('.')
        if len(parts) < 2:
            return False
        
        for part in parts:
            if not part or len(part) > 63:
                return False
            if not all(c.isalnum() or c == '-' for c in part):
                return False
            if part.startswith('-') or part.endswith('-'):
                return False
        
        return True

if __name__ == "__main__":
    detector = DomainDetector()
    detector.run()

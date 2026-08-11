import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

void main() => runApp(const RevenantApp());

class RevenantApp extends StatelessWidget {
  const RevenantApp({super.key});
  @override Widget build(BuildContext context) => MaterialApp(
    title: 'Revenant', debugShowCheckedModeBanner: false, theme: ThemeData.dark(useMaterial3: true),
    home: const Dashboard(),
  );
}

class Dashboard extends StatefulWidget { const Dashboard({super.key}); @override State<Dashboard> createState()=>_DashboardState(); }
class _DashboardState extends State<Dashboard> {
  final base='http://127.0.0.1:7878'; List devices=[]; String? job; Map<String,dynamic>? status; String mode='quick';
  Future<void> refresh() async { final r=await http.get(Uri.parse('$base/devices')); if(r.statusCode==200)setState(()=>devices=jsonDecode(r.body)); }
  Future<void> scan(String id) async { final r=await http.post(Uri.parse('$base/scans'),headers:{'Content-Type':'application/json'},body:jsonEncode({'device_id':id,'mode':mode})); if(r.statusCode<300){setState(()=>job=jsonDecode(r.body)['job_id']); _poll();} }
  Future<void> _poll() async { if(job==null)return; await Future.delayed(const Duration(milliseconds:700)); final r=await http.get(Uri.parse('$base/scans/$job')); if(r.statusCode==200){setState(()=>status=jsonDecode(r.body)); if(status!['status'].toString().contains('COMPLETED')==false && status!['status'].toString().contains('FAILED')==false && status!['status'].toString().contains('CANCELLED')==false)_poll();} }
  @override void initState(){super.initState();refresh();}
  @override Widget build(BuildContext c)=>Scaffold(appBar:AppBar(title:const Text('REVENANT'),subtitle:const Text('Data never truly dies.')),body:Padding(padding:const EdgeInsets.all(24),child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
    Row(children:[DropdownButton(value:mode,items:const [DropdownMenuItem(value:'quick',child:Text('Quick Scan')),DropdownMenuItem(value:'deep',child:Text('Deep Scan'))],onChanged:(v)=>setState(()=>mode=v!)),const SizedBox(width:20),ElevatedButton.icon(onPressed:refresh,icon:const Icon(Icons.refresh),label:const Text('Refresh devices'))]),
    const SizedBox(height:20),Expanded(child:ListView(children:[for(final d in devices)Card(child:ListTile(title:Text(d['name']??d['id']),subtitle:Text('${d['category']} • scan capable: ${d['scan_capable']}'),trailing:ElevatedButton(onPressed:d['scan_capable']==true?()=>scan(d['id']):null,child:const Text('Scan')))])),
    if(status!=null)Card(child:Padding(padding:const EdgeInsets.all(16),child:Text('Job ${status!['id']} • ${status!['status']} • ${status!['progress']} • ${status!['phase']}')))
  ])));
}

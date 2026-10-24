const $=id=>document.getElementById(id);let file=null;
function element(tag,text,cls){const el=document.createElement(tag);el.textContent=text;if(cls)el.className=cls;return el}
async function api(path,body,type='application/json'){const response=await fetch(path,{method:body===undefined?'GET':'POST',headers:{'Content-Type':type},body:body===undefined?undefined:type==='application/json'?JSON.stringify(body):body});const data=await response.json();if(!response.ok)throw new Error(typeof data.detail==='string'?data.detail:JSON.stringify(data.error||data.detail));return data}
function showError(exc){$('error').hidden=false;$('error').textContent=exc.message}
$('eml').onchange=()=>{file=$('eml').files[0]||null;$('filename').textContent=file?file.name:''};
function card(title,description){const div=element('div','','finding');div.append(element('strong',title),element('p',description));return div}
function render(report){
  const root=$('result');root.replaceChildren();
  const labels={high_risk:'High spam risk',needs_review:'Needs review',low_scanner_risk:'Low scanner risk',uncertain:'Uncertain'};
  const summary=element('div','','summary');summary.append(element('span',labels[report.verdict]||report.verdict));
  if(report.model_consensus?.available_models)summary.append(element('span',report.model_consensus.disagreement?'Models disagree':report.model_consensus.available_models+' content models compared'));
  root.append(summary);
  const scan=report.rspamd;const scanner=card('Rspamd',scan.available?'Action: '+scan.action+' · score '+scan.score:'Unavailable: '+scan.reason);
  if(scan.available)for(const [name,value] of Object.entries(scan.symbols||{}).sort((a,b)=>b[1].score-a[1].score).slice(0,15))scanner.append(element('p',name+': '+value.score));
  root.append(scanner);
  for(const model of report.content_models||[]){
    const item=card(model.id,model.available?'Verdict: '+model.verdict+' · uncalibrated spam score '+(100*model.probability).toFixed(1)+'% · '+model.device_used:'Unavailable: '+(model.error||model.reason));
    if(model.available)for(const sentence of (model.explanations||[]).slice(0,5))item.append(element('p',sentence.sentence+' (score delta '+sentence.score_delta.toFixed(3)+')'));
    root.append(item);
  }
  const optional=element('details','');optional.append(element('summary','Optional calibrated percentages'));
  optional.append(element('p','Enable measured local spam and Gmail estimates with labeled outcomes. The detector works without these estimates.'));
  const setup=element('a','Calibration setup guide');setup.href='/guides/calibration.md';optional.append(setup);
  for(const [key,title] of [['local_calibration','Calibrated local spam estimate'],['gmail_calibration','Gmail placement estimate']]){
    const estimate=report[key];
    const item=card(title,estimate?.available?(100*estimate.probability).toFixed(1)+'% · '+estimate.artifact_id:estimate?.reason==='calibration_not_configured'?'Not enabled. See the setup guide.':'Unavailable for this message: '+(estimate?.reason||'no validated artifact'));
    if(estimate?.available)root.append(item);else optional.append(item);
  }
  root.append(optional);
  for(const f of report.findings||[])root.append(card(f.code,f.evidence+' · '+f.recommended_action));
  const details=element('details','');details.append(element('summary','Full JSON report'),element('pre',JSON.stringify(report,null,2)));root.append(details);
}
$('test-spam').onclick=async()=>{$('test-spam').disabled=true;$('error').hidden=true;$('status').textContent='Running configured detectors…';$('result').replaceChildren(element('div','','skeleton'));try{let message;if(file)message=await api('/v1/messages?run_id=spam-ui',file,'message/rfc822');else message=await api('/v1/compose',{subject:$('subject').value,text:$('text').value,html:$('html').value,run_id:'spam-ui'});const context={explain:$('explain').checked};if($('sender-ip').value)context.sender_ip=$('sender-ip').value;if($('mail-from').value)context.mail_from=$('mail-from').value;const report=await api('/v1/messages/'+message.id+'/audit',context);render(report);$('status').textContent='Completed · message '+message.id}catch(exc){$('result').replaceChildren();showError(exc);$('status').textContent='Test failed'}finally{$('test-spam').disabled=false}};
api('/v1/capabilities').then(cap=>{$('availability').textContent=(cap.rspamd_configured?'Rspamd configured':'Rspamd unavailable')+' · '+(cap.content_models?.models.length||0)+' optional content models configured'}).catch(showError);
const importLabel=document.querySelector('label.button');importLabel.tabIndex=0;importLabel.setAttribute('role','button');importLabel.onkeydown=event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();$('eml').click()}};
const clearFile=element('button','Clear imported file');clearFile.hidden=true;$('filename').after(clearFile);clearFile.onclick=()=>{file=null;$('eml').value='';$('filename').textContent='';clearFile.hidden=true};$('eml').addEventListener('change',()=>{clearFile.hidden=!file});

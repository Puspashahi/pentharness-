'use strict';
const http=require('http');
const SCHEMA={data:{__schema:{queryType:{name:'Query'},mutationType:{name:'Mutation'},types:[
 {kind:'OBJECT',name:'Query',fields:[
   {name:'user',args:[{name:'id',type:{name:'ID'}}],type:{name:'User'}},
   {name:'me',args:[],type:{name:'User'}}]},
 {kind:'OBJECT',name:'Mutation',fields:[
   {name:'updateUser',args:[{name:'id',type:{name:'ID'}},{name:'email',type:{name:'String'}},{name:'role',type:{name:'String'}}],type:{name:'User'}}]},
 {kind:'OBJECT',name:'User',fields:[
   {name:'id',args:[],type:{name:'ID'}},
   {name:'email',args:[],type:{name:'String'}},
   {name:'adminNotes',args:[],type:{name:'String'}}]},
]}}};
http.createServer((req,res)=>{
 if(req.url.startsWith('/graphql')){
  let b='';req.on('data',c=>b+=c);return req.on('end',()=>{
   let q={};try{q=JSON.parse(b)}catch{}
   const query=(q.query||'');
   res.writeHead(200,{'Content-Type':'application/json'});
   if(/__schema/.test(query)) return res.end(JSON.stringify(SCHEMA));
   // The bug: user(id:) has no ownership check -> returns any user
   const mu=query.match(/user\(\s*id:\s*"?([^")]+)"?/);
   if(mu){const id=mu[1];
     if(String(id)==='999') return res.end(JSON.stringify({errors:[{message:'forbidden'}]}));
     const owner=(parseInt(id,10)||0)%2?'alice':'bob';
     return res.end(JSON.stringify({data:{user:{id,email:owner+'@corp.test',adminNotes:'internal: '+owner}}}));}
   const mmu=query.match(/updateUser\(/);
   if(mmu) return res.end(JSON.stringify({data:{updateUser:{id:'1',email:'x@corp.test',role:'admin'}}}));
   res.end(JSON.stringify({data:{}}));
  });
 }
 res.writeHead(404);res.end('nope');
}).listen(8097,'127.0.0.1',()=>console.log('graphql fixture on 8097'));

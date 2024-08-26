import { Injectable } from '@angular/core';
import { HttpInterceptor,HttpRequest,HttpHandler,HttpErrorResponse, HttpHeaders } from '@angular/common/http';
import {Router} from '@angular/router';
import {tap} from 'rxjs/operators';
import { User } from 'src/app/model/user.model';

//* 여기서 backend로 가는 모든 요청을 가로챔.
@Injectable()
export class XhrInterceptor implements HttpInterceptor {

  user = new User();
  constructor(private router: Router) {}

  intercept(req: HttpRequest<any>, next: HttpHandler) {
    let httpHeaders = new HttpHeaders();
    if(sessionStorage.getItem('userdetails')){
      this.user = JSON.parse(sessionStorage.getItem('userdetails')!);
    }
    //*  user가 처음 로그인 할 때
    if(this.user && this.user.password && this.user.email){
      //* btoa : base64인코딩 -> header에 보내면 BasicAuthenticationFilter에서 값을 잡아냄.
      httpHeaders = httpHeaders.append('Authorization', 'Basic ' + window.btoa(this.user.email + ':' + this.user.password));
    }else{
      //* 로그인 할 때 말고 다른 경우
      let authorization = sessionStorage.getItem('Authorization');
      if(authorization){
        httpHeaders = httpHeaders.append('Authorization',authorization);
      }
    }

    //! header의 name은 백엔드에서 쓰는 것과 동일하게!
    let xsrf = sessionStorage.getItem("XSRF-TOKEN");
    if(xsrf) {
      httpHeaders = httpHeaders.append('XSRF-TOKEN',xsrf);
    }

    httpHeaders = httpHeaders.append('X-Requested-With', 'XMLHttpRequest');
    const xhr = req.clone({
      headers: httpHeaders
    });
  return next.handle(xhr).pipe(tap(
      (err: any) => {
        if (err instanceof HttpErrorResponse) {
          if (err.status !== 401) {
            return;
          }
          this.router.navigate(['dashboard']);
        }
      }));
  }
}
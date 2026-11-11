// ============================================================================
// CATHY'S ANGULAR 21 PORTFOLIO — CLASS 1 (October 21, 2026)
// Topic: @Component, {{ }} Interpolation, (click) Event Binding, and 'this.'
// ============================================================================

import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  template: `
    <h1>Hello, {{ name }}!!</h1>
    <h2>Total = {{ total }}</h2>
    <button (click)="Add2numbers()">Add 10 + 10!</button>
  `
})
export class App {
  name = 'Cathy the Angular Pro';
  num1 = 10;
  num2 = 10;
  total = 0;

  Add2numbers() {
    this.total = this.num1 + this.num2;
  }
}

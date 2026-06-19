import { ComponentFixture, TestBed } from '@angular/core/testing';

import { MetricsPanelComponent } from './metrics-panel.component';

describe('MetricsPanelComponent', () => {
  let component: MetricsPanelComponent;
  let fixture: ComponentFixture<MetricsPanelComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [MetricsPanelComponent]
    })
    .compileComponents();

    fixture = TestBed.createComponent(MetricsPanelComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});

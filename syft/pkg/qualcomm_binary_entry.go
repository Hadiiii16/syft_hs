package pkg

// QualcommBinaryEntry는 Qualcomm 상용 바이너리(.so/.ko)에서
// 추출한 컴포넌트 정보입니다.
type QualcommBinaryEntry struct {
	Supplier   string   `json:"supplier" yaml:"supplier" mapstructure:"supplier"`
	SHA256     string   `json:"sha256" yaml:"sha256" mapstructure:"sha256"`
	SONAME     string   `json:"soname,omitempty" yaml:"soname,omitempty" mapstructure:"soname"`
	Chipset    string   `json:"chipset,omitempty"`   // ← 추가
	Confidence float64  `json:"confidence" yaml:"confidence" mapstructure:"confidence"`
	Evidence   []string `json:"evidence,omitempty" yaml:"evidence,omitempty" mapstructure:"evidence"`
}
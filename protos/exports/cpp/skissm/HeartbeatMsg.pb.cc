// Generated by the protocol buffer compiler.  DO NOT EDIT!
// source: skissm/HeartbeatMsg.proto

#include "skissm/HeartbeatMsg.pb.h"

#include <algorithm>

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/extension_set.h>
#include <google/protobuf/wire_format_lite.h>
#include <google/protobuf/descriptor.h>
#include <google/protobuf/generated_message_reflection.h>
#include <google/protobuf/reflection_ops.h>
#include <google/protobuf/wire_format.h>
// @@protoc_insertion_point(includes)
#include <google/protobuf/port_def.inc>

PROTOBUF_PRAGMA_INIT_SEG
namespace skissm {
constexpr HeartbeatMsg::HeartbeatMsg(
  ::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized)
  : hostname_(&::PROTOBUF_NAMESPACE_ID::internal::fixed_address_empty_string)
  , server_t_(int64_t{0}){}
struct HeartbeatMsgDefaultTypeInternal {
  constexpr HeartbeatMsgDefaultTypeInternal()
    : _instance(::PROTOBUF_NAMESPACE_ID::internal::ConstantInitialized{}) {}
  ~HeartbeatMsgDefaultTypeInternal() {}
  union {
    HeartbeatMsg _instance;
  };
};
PROTOBUF_ATTRIBUTE_NO_DESTROY PROTOBUF_CONSTINIT HeartbeatMsgDefaultTypeInternal _HeartbeatMsg_default_instance_;
}  // namespace skissm
static ::PROTOBUF_NAMESPACE_ID::Metadata file_level_metadata_skissm_2fHeartbeatMsg_2eproto[1];
static constexpr ::PROTOBUF_NAMESPACE_ID::EnumDescriptor const** file_level_enum_descriptors_skissm_2fHeartbeatMsg_2eproto = nullptr;
static constexpr ::PROTOBUF_NAMESPACE_ID::ServiceDescriptor const** file_level_service_descriptors_skissm_2fHeartbeatMsg_2eproto = nullptr;

const uint32_t TableStruct_skissm_2fHeartbeatMsg_2eproto::offsets[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  ~0u,  // no _has_bits_
  PROTOBUF_FIELD_OFFSET(::skissm::HeartbeatMsg, _internal_metadata_),
  ~0u,  // no _extensions_
  ~0u,  // no _oneof_case_
  ~0u,  // no _weak_field_map_
  ~0u,  // no _inlined_string_donated_
  PROTOBUF_FIELD_OFFSET(::skissm::HeartbeatMsg, hostname_),
  PROTOBUF_FIELD_OFFSET(::skissm::HeartbeatMsg, server_t_),
};
static const ::PROTOBUF_NAMESPACE_ID::internal::MigrationSchema schemas[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) = {
  { 0, -1, -1, sizeof(::skissm::HeartbeatMsg)},
};

static ::PROTOBUF_NAMESPACE_ID::Message const * const file_default_instances[] = {
  reinterpret_cast<const ::PROTOBUF_NAMESPACE_ID::Message*>(&::skissm::_HeartbeatMsg_default_instance_),
};

const char descriptor_table_protodef_skissm_2fHeartbeatMsg_2eproto[] PROTOBUF_SECTION_VARIABLE(protodesc_cold) =
  "\n\031skissm/HeartbeatMsg.proto\022\006skissm\"2\n\014H"
  "eartbeatMsg\022\020\n\010hostname\030\001 \001(\t\022\020\n\010server_"
  "t\030\002 \001(\003B-\n\030org.e2eelab.skissm.protoB\021Hea"
  "rtbeatMsgProtob\006proto3"
  ;
static ::PROTOBUF_NAMESPACE_ID::internal::once_flag descriptor_table_skissm_2fHeartbeatMsg_2eproto_once;
const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable descriptor_table_skissm_2fHeartbeatMsg_2eproto = {
  false, false, 142, descriptor_table_protodef_skissm_2fHeartbeatMsg_2eproto, "skissm/HeartbeatMsg.proto", 
  &descriptor_table_skissm_2fHeartbeatMsg_2eproto_once, nullptr, 0, 1,
  schemas, file_default_instances, TableStruct_skissm_2fHeartbeatMsg_2eproto::offsets,
  file_level_metadata_skissm_2fHeartbeatMsg_2eproto, file_level_enum_descriptors_skissm_2fHeartbeatMsg_2eproto, file_level_service_descriptors_skissm_2fHeartbeatMsg_2eproto,
};
PROTOBUF_ATTRIBUTE_WEAK const ::PROTOBUF_NAMESPACE_ID::internal::DescriptorTable* descriptor_table_skissm_2fHeartbeatMsg_2eproto_getter() {
  return &descriptor_table_skissm_2fHeartbeatMsg_2eproto;
}

// Force running AddDescriptors() at dynamic initialization time.
PROTOBUF_ATTRIBUTE_INIT_PRIORITY static ::PROTOBUF_NAMESPACE_ID::internal::AddDescriptorsRunner dynamic_init_dummy_skissm_2fHeartbeatMsg_2eproto(&descriptor_table_skissm_2fHeartbeatMsg_2eproto);
namespace skissm {

// ===================================================================

class HeartbeatMsg::_Internal {
 public:
};

HeartbeatMsg::HeartbeatMsg(::PROTOBUF_NAMESPACE_ID::Arena* arena,
                         bool is_message_owned)
  : ::PROTOBUF_NAMESPACE_ID::Message(arena, is_message_owned) {
  SharedCtor();
  if (!is_message_owned) {
    RegisterArenaDtor(arena);
  }
  // @@protoc_insertion_point(arena_constructor:skissm.HeartbeatMsg)
}
HeartbeatMsg::HeartbeatMsg(const HeartbeatMsg& from)
  : ::PROTOBUF_NAMESPACE_ID::Message() {
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
  hostname_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
  #ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
    hostname_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
  #endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
  if (!from._internal_hostname().empty()) {
    hostname_.Set(::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::EmptyDefault{}, from._internal_hostname(), 
      GetArenaForAllocation());
  }
  server_t_ = from.server_t_;
  // @@protoc_insertion_point(copy_constructor:skissm.HeartbeatMsg)
}

inline void HeartbeatMsg::SharedCtor() {
hostname_.UnsafeSetDefault(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
#ifdef PROTOBUF_FORCE_COPY_DEFAULT_STRING
  hostname_.Set(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(), "", GetArenaForAllocation());
#endif // PROTOBUF_FORCE_COPY_DEFAULT_STRING
server_t_ = int64_t{0};
}

HeartbeatMsg::~HeartbeatMsg() {
  // @@protoc_insertion_point(destructor:skissm.HeartbeatMsg)
  if (GetArenaForAllocation() != nullptr) return;
  SharedDtor();
  _internal_metadata_.Delete<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

inline void HeartbeatMsg::SharedDtor() {
  GOOGLE_DCHECK(GetArenaForAllocation() == nullptr);
  hostname_.DestroyNoArena(&::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited());
}

void HeartbeatMsg::ArenaDtor(void* object) {
  HeartbeatMsg* _this = reinterpret_cast< HeartbeatMsg* >(object);
  (void)_this;
}
void HeartbeatMsg::RegisterArenaDtor(::PROTOBUF_NAMESPACE_ID::Arena*) {
}
void HeartbeatMsg::SetCachedSize(int size) const {
  _cached_size_.Set(size);
}

void HeartbeatMsg::Clear() {
// @@protoc_insertion_point(message_clear_start:skissm.HeartbeatMsg)
  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  hostname_.ClearToEmpty();
  server_t_ = int64_t{0};
  _internal_metadata_.Clear<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>();
}

const char* HeartbeatMsg::_InternalParse(const char* ptr, ::PROTOBUF_NAMESPACE_ID::internal::ParseContext* ctx) {
#define CHK_(x) if (PROTOBUF_PREDICT_FALSE(!(x))) goto failure
  while (!ctx->Done(&ptr)) {
    uint32_t tag;
    ptr = ::PROTOBUF_NAMESPACE_ID::internal::ReadTag(ptr, &tag);
    switch (tag >> 3) {
      // string hostname = 1;
      case 1:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 10)) {
          auto str = _internal_mutable_hostname();
          ptr = ::PROTOBUF_NAMESPACE_ID::internal::InlineGreedyStringParser(str, ptr, ctx);
          CHK_(::PROTOBUF_NAMESPACE_ID::internal::VerifyUTF8(str, "skissm.HeartbeatMsg.hostname"));
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      // int64 server_t = 2;
      case 2:
        if (PROTOBUF_PREDICT_TRUE(static_cast<uint8_t>(tag) == 16)) {
          server_t_ = ::PROTOBUF_NAMESPACE_ID::internal::ReadVarint64(&ptr);
          CHK_(ptr);
        } else
          goto handle_unusual;
        continue;
      default:
        goto handle_unusual;
    }  // switch
  handle_unusual:
    if ((tag == 0) || ((tag & 7) == 4)) {
      CHK_(ptr);
      ctx->SetLastTag(tag);
      goto message_done;
    }
    ptr = UnknownFieldParse(
        tag,
        _internal_metadata_.mutable_unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(),
        ptr, ctx);
    CHK_(ptr != nullptr);
  }  // while
message_done:
  return ptr;
failure:
  ptr = nullptr;
  goto message_done;
#undef CHK_
}

uint8_t* HeartbeatMsg::_InternalSerialize(
    uint8_t* target, ::PROTOBUF_NAMESPACE_ID::io::EpsCopyOutputStream* stream) const {
  // @@protoc_insertion_point(serialize_to_array_start:skissm.HeartbeatMsg)
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  // string hostname = 1;
  if (!this->_internal_hostname().empty()) {
    ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::VerifyUtf8String(
      this->_internal_hostname().data(), static_cast<int>(this->_internal_hostname().length()),
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::SERIALIZE,
      "skissm.HeartbeatMsg.hostname");
    target = stream->WriteStringMaybeAliased(
        1, this->_internal_hostname(), target);
  }

  // int64 server_t = 2;
  if (this->_internal_server_t() != 0) {
    target = stream->EnsureSpace(target);
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::WriteInt64ToArray(2, this->_internal_server_t(), target);
  }

  if (PROTOBUF_PREDICT_FALSE(_internal_metadata_.have_unknown_fields())) {
    target = ::PROTOBUF_NAMESPACE_ID::internal::WireFormat::InternalSerializeUnknownFieldsToArray(
        _internal_metadata_.unknown_fields<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(::PROTOBUF_NAMESPACE_ID::UnknownFieldSet::default_instance), target, stream);
  }
  // @@protoc_insertion_point(serialize_to_array_end:skissm.HeartbeatMsg)
  return target;
}

size_t HeartbeatMsg::ByteSizeLong() const {
// @@protoc_insertion_point(message_byte_size_start:skissm.HeartbeatMsg)
  size_t total_size = 0;

  uint32_t cached_has_bits = 0;
  // Prevent compiler warnings about cached_has_bits being unused
  (void) cached_has_bits;

  // string hostname = 1;
  if (!this->_internal_hostname().empty()) {
    total_size += 1 +
      ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::StringSize(
        this->_internal_hostname());
  }

  // int64 server_t = 2;
  if (this->_internal_server_t() != 0) {
    total_size += ::PROTOBUF_NAMESPACE_ID::internal::WireFormatLite::Int64SizePlusOne(this->_internal_server_t());
  }

  return MaybeComputeUnknownFieldsSize(total_size, &_cached_size_);
}

const ::PROTOBUF_NAMESPACE_ID::Message::ClassData HeartbeatMsg::_class_data_ = {
    ::PROTOBUF_NAMESPACE_ID::Message::CopyWithSizeCheck,
    HeartbeatMsg::MergeImpl
};
const ::PROTOBUF_NAMESPACE_ID::Message::ClassData*HeartbeatMsg::GetClassData() const { return &_class_data_; }

void HeartbeatMsg::MergeImpl(::PROTOBUF_NAMESPACE_ID::Message* to,
                      const ::PROTOBUF_NAMESPACE_ID::Message& from) {
  static_cast<HeartbeatMsg *>(to)->MergeFrom(
      static_cast<const HeartbeatMsg &>(from));
}


void HeartbeatMsg::MergeFrom(const HeartbeatMsg& from) {
// @@protoc_insertion_point(class_specific_merge_from_start:skissm.HeartbeatMsg)
  GOOGLE_DCHECK_NE(&from, this);
  uint32_t cached_has_bits = 0;
  (void) cached_has_bits;

  if (!from._internal_hostname().empty()) {
    _internal_set_hostname(from._internal_hostname());
  }
  if (from._internal_server_t() != 0) {
    _internal_set_server_t(from._internal_server_t());
  }
  _internal_metadata_.MergeFrom<::PROTOBUF_NAMESPACE_ID::UnknownFieldSet>(from._internal_metadata_);
}

void HeartbeatMsg::CopyFrom(const HeartbeatMsg& from) {
// @@protoc_insertion_point(class_specific_copy_from_start:skissm.HeartbeatMsg)
  if (&from == this) return;
  Clear();
  MergeFrom(from);
}

bool HeartbeatMsg::IsInitialized() const {
  return true;
}

void HeartbeatMsg::InternalSwap(HeartbeatMsg* other) {
  using std::swap;
  auto* lhs_arena = GetArenaForAllocation();
  auto* rhs_arena = other->GetArenaForAllocation();
  _internal_metadata_.InternalSwap(&other->_internal_metadata_);
  ::PROTOBUF_NAMESPACE_ID::internal::ArenaStringPtr::InternalSwap(
      &::PROTOBUF_NAMESPACE_ID::internal::GetEmptyStringAlreadyInited(),
      &hostname_, lhs_arena,
      &other->hostname_, rhs_arena
  );
  swap(server_t_, other->server_t_);
}

::PROTOBUF_NAMESPACE_ID::Metadata HeartbeatMsg::GetMetadata() const {
  return ::PROTOBUF_NAMESPACE_ID::internal::AssignDescriptors(
      &descriptor_table_skissm_2fHeartbeatMsg_2eproto_getter, &descriptor_table_skissm_2fHeartbeatMsg_2eproto_once,
      file_level_metadata_skissm_2fHeartbeatMsg_2eproto[0]);
}

// @@protoc_insertion_point(namespace_scope)
}  // namespace skissm
PROTOBUF_NAMESPACE_OPEN
template<> PROTOBUF_NOINLINE ::skissm::HeartbeatMsg* Arena::CreateMaybeMessage< ::skissm::HeartbeatMsg >(Arena* arena) {
  return Arena::CreateMessageInternal< ::skissm::HeartbeatMsg >(arena);
}
PROTOBUF_NAMESPACE_CLOSE

// @@protoc_insertion_point(global_scope)
#include <google/protobuf/port_undef.inc>